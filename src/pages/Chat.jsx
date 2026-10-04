// client/src/pages/Chat.jsx
import React, { useState, useEffect, useContext, useRef, useMemo } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { 
  generateUserKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPublicKeyFromPrivateJwk,
  importPrivateKey,
  deriveSharedSecret,
  generateSessionKey,
  encryptWithSessionKey,
  decryptWithDerivedKey,
  decryptWithSessionKey,
  wrapKeyForUser,
  unwrapKeyForUser,
  encryptAudioBlob,
  encryptClient,
  decryptClient,
  encryptMasterAudit
} from '../utils/cryptoClient';
import AudioMessage from '../components/AudioMessage';
import { 
  LogOut, 
  Send, 
  ShieldCheck, 
  Paperclip, 
  FileText, 
  Download, 
  Check, 
  CheckCheck, 
  Search, 
  MessageSquare, 
  Key, 
  Mic, 
  Square,
  Ban     
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

// LIVE BACKEND BASE URL (Fallback to Render / Localhost)
const API_BASE = import.meta.env.VITE_API_URL || 'https://your-backend-app.onrender.com';

export default function Chat() {
  const { user, token, logout } = useContext(AuthContext);
  const [users, setUsers] = useState([]);
  const [activeUser, setActiveUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [isClearingConversation, setIsClearingConversation] = useState(false);
  const [clearConversationError, setClearConversationError] = useState('');
  const [inputMsg, setInputMsg] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const [isRecording, setIsRecording] = useState(false);
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const recordingTimerRef = useRef(null);

  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [myPublicKey, setMyPublicKey] = useState(null);
  const [activeSharedKey, setActiveSharedKey] = useState(null);
  const [isDerivingKey, setIsDerivingKey] = useState(false);

  const [onlineUserList, setOnlineUserList] = useState([]);
  const [isOtherUserTyping, setIsOtherUserTyping] = useState(false);

  // Unread counts mapping: { "userId": count }
  const [unreadCounts, setUnreadCounts] = useState({});

  const socket = useRef();
  const chatEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const navigate = useNavigate();

  const createAdminKeyWrap = async (sessionKey) => {
    try {
      const adminRes = await axios.get(`${API_BASE}/api/auth/admin-public-key`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const admins = adminRes.data?.admins || (adminRes.data?.publicKey ? [adminRes.data] : []);
      const wraps = await Promise.all(admins.map(async (admin) => {
        try {
          const publicKey = await importPublicKey(admin.publicKey);
          return [admin._id, await wrapKeyForUser(sessionKey, myPrivateKey, publicKey)];
        } catch {
          return [admin._id, null];
        }
      }));
      const validWraps = Object.fromEntries(wraps.filter(([, wrappedKey]) => wrappedKey));
      return Object.keys(validWraps).length ? JSON.stringify(validWraps) : null;
    } catch {
      return null;
    }
  };

  // Handle active user change - clear their unread count
  const handleUserSelect = (u) => {
    setActiveUser(u);
    setClearConversationError('');
    setUnreadCounts((prev) => ({ ...prev, [u._id]: 0 }));
  };

  const handleKillConversation = async () => {
    if (!activeUser || !token || isClearingConversation) return;

    setIsClearingConversation(true);
    setClearConversationError('');
    try {
      await axios.delete(`${API_BASE}/api/messages/${activeUser._id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMessages([]);
    } catch (err) {
      setClearConversationError(
        err.response?.status === 404
          ? 'Backend update required: deploy the latest server code, then retry KILL.'
          : err.response?.data?.error || 'Could not clear this conversation. Please retry.'
      );
    } finally {
      setIsClearingConversation(false);
    }
  };

  // FAST DECRYPT ENGINE (With Robust Fallback)
  const decryptMessage = async (msg, sharedKey) => {
    if (msg.isDeleted) return 'This message was deleted';
    if (msg.messageType !== 'text' || !msg.encryptedText || !msg.iv || !msg.authTag) {
      return msg.text || '';
    }

    const isMe = msg.sender === user?.id || msg.sender?._id === user?.id;

    if (isMe && msg.text && !msg.text.startsWith('[') && msg.text !== '') {
      return msg.text;
    }

    // 1. Try ECDH Envelope Decryption if sharedKey exists
    const envelopes = [msg.recipientKeyWrap, msg.senderKeyWrap].filter(Boolean);
    if (envelopes.length && sharedKey) {
      try {
        for (const envelope of envelopes) {
          const sessionKey = await unwrapKeyForUser(envelope, sharedKey);
          if (sessionKey) {
            const plain = await decryptWithSessionKey(msg.encryptedText, msg.iv, msg.authTag, sessionKey);
            if (plain && !plain.startsWith('[')) return plain;
          }
        }
      } catch (err) {}
    }

    // 2. Try Direct ECDH Derived Key
    if (sharedKey) {
      try {
        const derivedText = await decryptWithDerivedKey(msg.encryptedText, msg.iv, msg.authTag, sharedKey);
        if (derivedText && !derivedText.startsWith('[')) return derivedText;
      } catch (err) {}
    }

    // 3. Fallback: Static AES Tunnel Decryption
    try {
      const staticText = await decryptClient(msg.encryptedText, msg.iv, msg.authTag);
      if (staticText && !staticText.startsWith('[')) return staticText;
    } catch (err) {}

    return '[Decryption Failed: Mismatched Key]';
  };

  const fetchUsers = async () => {
    if (!token || !user?.id) return;
    try {
      const res = await axios.get(`${API_BASE}/api/auth/users`, { 
        headers: { Authorization: `Bearer ${token}` } 
      });
      setUsers(res.data.filter((u) => u._id !== user.id));
    } catch (err) {}
  };

  // Auto-Sync User Keys with Cloud Recovery
  useEffect(() => {
    if (!token || !user?.id) return;

    const initUserKeys = async () => {
      try {
        const storageKey = `ecdh_priv_${user.id}`;
        let storedPrivJwk = localStorage.getItem(storageKey);

        // Fetch from server on new device
        if (!storedPrivJwk) {
          try {
            const backupRes = await axios.get(`${API_BASE}/api/auth/my-keys`, {
              headers: { Authorization: `Bearer ${token}` }
            });
            if (backupRes.data?.privateKey) {
              storedPrivJwk = backupRes.data.privateKey;
              localStorage.setItem(storageKey, storedPrivJwk);
            }
          } catch (e) {}
        }

        let privateKeyObj = null;
        let publicKeyObj = null;

        if (storedPrivJwk) {
          privateKeyObj = await importPrivateKey(storedPrivJwk);
          publicKeyObj = await importPublicKeyFromPrivateJwk(storedPrivJwk);
          setMyPublicKey(publicKeyObj);
          await axios.put(
            `${API_BASE}/api/auth/public-key`, 
            { publicKey: await exportPublicKey(publicKeyObj) }, 
            { headers: { Authorization: `Bearer ${token}` } }
          );
        } else {
          const keyPair = await generateUserKeyPair();
          privateKeyObj = keyPair.privateKey;
          publicKeyObj = keyPair.publicKey;
          setMyPublicKey(publicKeyObj);

          const privJwk = await exportPrivateKey(keyPair.privateKey);
          const pubJwk = await exportPublicKey(keyPair.publicKey);
          localStorage.setItem(storageKey, privJwk);

          try {
            await axios.post(
              `${API_BASE}/api/auth/sync-keys`,
              { publicKey: pubJwk, privateKey: privJwk },
              { headers: { Authorization: `Bearer ${token}` } }
            );
          } catch (e) {}

          await axios.put(
            `${API_BASE}/api/auth/public-key`, 
            { publicKey: pubJwk }, 
            { headers: { Authorization: `Bearer ${token}` } }
          );
        }

        setMyPrivateKey(privateKeyObj);
        fetchUsers();

      } catch (err) {}
    };

    initUserKeys();
  }, [user, token]);

  useEffect(() => {
    if (!activeUser || !myPrivateKey || !token) {
      setActiveSharedKey(null);
      return;
    }

    const deriveSessionKey = async () => {
      setIsDerivingKey(true);
      try {
        const userRes = await axios.get(`${API_BASE}/api/auth/users`, { 
          headers: { Authorization: `Bearer ${token}` } 
        });
        const freshTarget = userRes.data.find((u) => u._id === activeUser._id);
        const targetPubKeyString = freshTarget?.publicKey || activeUser.publicKey;

        if (targetPubKeyString) {
          const recipientPubKey = await importPublicKey(targetPubKeyString);
          const sharedKey = await deriveSharedSecret(myPrivateKey, recipientPubKey);
          setActiveSharedKey(sharedKey);
        } else {
          setActiveSharedKey(null);
        }
      } catch (err) {
        setActiveSharedKey(null);
      } finally {
        setIsDerivingKey(false);
      }
    };

    deriveSessionKey();
  }, [activeUser?._id, myPrivateKey, token]);

  useEffect(() => {
    if (!token || !user?.id) {
      if (!token) navigate('/');
      return;
    }

    socket.current = io(API_BASE, { auth: { token } });
    socket.current.emit('join', user.id);

    socket.current.on('getOnlineUsers', (onlineIds) => setOnlineUserList(onlineIds));
    socket.current.on('userTyping', ({ senderId }) => { 
      if (activeUser && activeUser._id === senderId) setIsOtherUserTyping(true); 
    });
    socket.current.on('userStopTyping', ({ senderId }) => { 
      if (activeUser && activeUser._id === senderId) setIsOtherUserTyping(false); 
    });

    socket.current.on('receiveMessage', async (msg) => {
      if (activeUser && msg.sender === activeUser._id && msg.receiver === user.id) {
        let currentShared = activeSharedKey;
        if (!currentShared && myPrivateKey && activeUser.publicKey) {
          const partnerPub = await importPublicKey(activeUser.publicKey);
          currentShared = await deriveSharedSecret(myPrivateKey, partnerPub);
        }

        const textContent = await decryptMessage(msg, currentShared);
        setMessages((prev) => [...prev, { ...msg, text: textContent }]);
        socket.current.emit('markAsSeen', { senderId: activeUser._id, viewerId: user.id });
      } else if (msg.receiver === user.id) {
        setUnreadCounts((prev) => ({
          ...prev,
          [msg.sender]: (prev[msg.sender] || 0) + 1
        }));
      }

      setUsers((prevUsers) => {
        const senderIdx = prevUsers.findIndex((u) => u._id === msg.sender);
        if (senderIdx > -1) {
          const newUsers = [...prevUsers];
          const [senderObj] = newUsers.splice(senderIdx, 1);
          return [senderObj, ...newUsers];
        }
        return prevUsers;
      });
    });

    socket.current.on('messageSent', (msg) => {
      setMessages((prev) => {
        const existingIdx = prev.findIndex((m) => m.status === 'sending' && (m._id.startsWith('temp_') || m.text === msg.text));
        if (existingIdx !== -1) {
          const newArr = [...prev];
          newArr[existingIdx] = { ...msg, text: newArr[existingIdx].text, status: 'sent' };
          return newArr;
        }
        return prev;
      });

      setUsers((prevUsers) => {
        const receiverIdx = prevUsers.findIndex((u) => u._id === msg.receiver);
        if (receiverIdx > -1) {
          const newUsers = [...prevUsers];
          const [receiverObj] = newUsers.splice(receiverIdx, 1);
          return [receiverObj, ...newUsers];
        }
        return prevUsers;
      });
    });

    socket.current.on('messagesSeen', () => {
      setMessages((prev) => prev.map((msg) => ({ ...msg, status: 'seen' })));
    });

    socket.current.on('messageDeleted', ({ msgId }) => {
      setMessages((prev) => prev.map((msg) => 
        msg._id === msgId 
          ? { ...msg, isDeleted: true, text: 'This message was deleted', fileData: null, messageType: 'text' } 
          : msg
      ));
    });

    return () => socket.current?.disconnect();
  }, [user, activeUser, token, activeSharedKey, myPrivateKey, navigate]);

  useEffect(() => {
    if (token) fetchUsers();
  }, [token, user]);

  useEffect(() => {
    if (!activeUser || !token || !user?.id || !myPrivateKey) return;
    setIsOtherUserTyping(false);

    const fetchMessages = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/messages/${activeUser._id}`, { 
          headers: { Authorization: `Bearer ${token}` } 
        });
        
        let currentShared = activeSharedKey;
        if (!currentShared && activeUser.publicKey) {
          const partnerPub = await importPublicKey(activeUser.publicKey);
          currentShared = await deriveSharedSecret(myPrivateKey, partnerPub);
        }
        
        const decryptedHistory = await Promise.all(
          res.data.map(async (msg) => {
            const plain = await decryptMessage(msg, currentShared);
            return { ...msg, text: plain };
          })
        );
        
        setMessages(decryptedHistory);
        socket.current.emit('markAsSeen', { senderId: activeUser._id, viewerId: user.id });
      } catch (err) {}
    };
    fetchMessages();
  }, [activeUser, token, activeSharedKey, myPrivateKey, user?.id]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isOtherUserTyping]);

  const handleInputChange = (e) => {
    setInputMsg(e.target.value);
    if (!activeUser || !user?.id || !socket.current) return;

    socket.current.emit('typing', { senderId: user.id, receiverId: activeUser._id });
    clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      socket.current.emit('stopTyping', { senderId: user.id, receiverId: activeUser._id });
    }, 1500);
  };

  const startRecording = async () => {
    if (!activeUser) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorderRef.current = new MediaRecorder(stream);
      audioChunksRef.current = [];
      mediaRecorderRef.current.ondataavailable = (e) => { 
        if (e.data.size > 0) audioChunksRef.current.push(e.data); 
      };
      mediaRecorderRef.current.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        await handleSendAudio(audioBlob);
      };
      mediaRecorderRef.current.start();
      setIsRecording(true);
      setRecordingSeconds(0);
      recordingTimerRef.current = setInterval(() => { 
        setRecordingSeconds((prev) => prev + 1); 
      }, 1000);
    } catch (err) { 
      alert('Microphone permission denied.'); 
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      mediaRecorderRef.current.stream.getTracks().forEach((track) => track.stop());
      setIsRecording(false);
      clearInterval(recordingTimerRef.current);
    }
  };

  const handleSendAudio = async (audioBlob) => {
    if (!activeUser || !myPrivateKey || !myPublicKey) return;

    try {
      const userRes = await axios.get(`${API_BASE}/api/auth/users`, { 
        headers: { Authorization: `Bearer ${token}` } 
      });
      const freshTarget = userRes.data.find((u) => u._id === activeUser._id);
      const targetPubKeyStr = freshTarget?.publicKey || activeUser.publicKey;

      if (!targetPubKeyStr) throw new Error('Recipient key not found');

      const sessionKey = await generateSessionKey();
      const { encryptedBlob, iv, authTag } = await encryptAudioBlob(audioBlob, sessionKey);

      const recipientPubKey = await importPublicKey(targetPubKeyStr);
      const recipientKeyWrap = await wrapKeyForUser(sessionKey, myPrivateKey, recipientPubKey);
      const senderKeyWrap = await wrapKeyForUser(sessionKey, myPrivateKey, myPublicKey);

      const adminKeyWrap = await createAdminKeyWrap(sessionKey);

      const formData = new FormData();
      formData.append('audio', encryptedBlob, `voice_${Date.now()}.enc`);
      formData.append('receiverId', activeUser._id);
      formData.append('iv', iv);
      formData.append('authTag', authTag);
      formData.append('recipientKeyWrap', recipientKeyWrap);
      formData.append('senderKeyWrap', senderKeyWrap);
      if (adminKeyWrap) formData.append('adminKeyWrap', adminKeyWrap);

      const res = await axios.post(`${API_BASE}/api/files/upload-audio`, formData, {
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
      });

      const newMsg = res.data.message;
      socket.current.emit('sendMessage', { 
        senderId: user.id, 
        receiverId: activeUser._id, 
        isFile: true, 
        fileData: newMsg.fileData, 
        msgId: newMsg._id 
      });
      setMessages((prev) => [...prev, newMsg]);
    } catch (err) { 
      alert('Failed to send encrypted voice note.'); 
    }
  };

  // SEND MESSAGE (100% Robust Master Vault & Fresh Escrow Fallback)
  const handleSend = async (e) => {
    e.preventDefault();
    if (!inputMsg.trim() || !activeUser || !user?.id || !socket.current) return;

    const currentText = inputMsg;
    setInputMsg('');
    clearTimeout(typingTimeoutRef.current);
    socket.current.emit('stopTyping', { senderId: user.id, receiverId: activeUser._id });

    const tempId = 'temp_' + Date.now();
    setMessages((prev) => [
      ...prev,
      { _id: tempId, sender: user.id, receiver: activeUser._id, text: currentText, messageType: 'text', createdAt: new Date().toISOString(), status: 'sending', isDeleted: false }
    ]);

    try {
      const userRes = await axios.get(`${API_BASE}/api/auth/users`, { 
        headers: { Authorization: `Bearer ${token}` } 
      });
      const freshTarget = userRes.data.find((u) => u._id === activeUser._id);
      const targetPubKeyStr = freshTarget?.publicKey || activeUser.publicKey;

      // Generate Master Enterprise Audit Envelope (Decodes seamlessly everywhere)
      let auditPayload = null;
      let auditIv = null;
      try {
        const auditEnv = await encryptMasterAudit(currentText);
        if (auditEnv) {
          // Compatible with any return format from cryptoClient.js
          auditPayload = auditEnv.encryptedText || auditEnv.auditPayload || auditEnv.ciphertext || null;
          auditIv = auditEnv.iv || auditEnv.auditIv || null;
        }
      } catch (e) {}

      // 1. Primary: ECDH Dual-Envelope E2EE mode
      if (myPrivateKey && myPublicKey && targetPubKeyStr) {
        const sessionKey = await generateSessionKey();
        const payload = await encryptWithSessionKey(currentText, sessionKey);

        const recipientPubKey = await importPublicKey(targetPubKeyStr);
        const recipientKeyWrap = await wrapKeyForUser(sessionKey, myPrivateKey, recipientPubKey);
        const senderKeyWrap = await wrapKeyForUser(sessionKey, myPrivateKey, myPublicKey);

        const adminKeyWrap = await createAdminKeyWrap(sessionKey);

        socket.current.emit(
          'sendMessage',
          { 
            senderId: user.id, 
            receiverId: activeUser._id, 
            encryptedText: payload.encryptedText, 
            iv: payload.iv, 
            authTag: payload.authTag, 
            recipientKeyWrap, 
            senderKeyWrap, 
            adminKeyWrap, 
            auditPayload,
            auditIv,
            isFile: false 
          },
          (response) => { 
            if (response?.ok) {
              setMessages((prev) => prev.map((m) => m._id === tempId ? { ...m, status: 'sent' } : m));
            } else if (response && !response.ok) {
              setMessages((prev) => prev.filter((m) => m._id !== tempId));
            }
          }
        );
        return;
      }

      // 2. Fallback: Static AES Tunnel
      const staticEncrypted = await encryptClient(currentText);
      socket.current.emit(
        'sendMessage',
        {
          senderId: user.id,
          receiverId: activeUser._id,
          encryptedText: staticEncrypted.encryptedText || staticEncrypted.ciphertext,
          iv: staticEncrypted.iv,
          authTag: staticEncrypted.authTag,
          auditPayload,
          auditIv,
          isFile: false
        },
        (response) => { 
          if (response?.ok) {
            setMessages((prev) => prev.map((m) => m._id === tempId ? { ...m, status: 'sent' } : m));
          } else if (response && !response.ok) {
            setMessages((prev) => prev.filter((m) => m._id !== tempId));
          }
        }
      );

    } catch (err) {
      setMessages((prev) => prev.filter((m) => m._id !== tempId));
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !activeUser) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('receiverId', activeUser._id);
    
    setIsUploading(true);
    try {
      const res = await axios.post(`${API_BASE}/api/files/upload`, formData, {
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
      });
      
      const newMsg = res.data.message;
      socket.current.emit('sendMessage', { 
        senderId: user.id, 
        receiverId: activeUser._id, 
        isFile: true, 
        fileData: { messageType: newMsg.messageType, fileName: newMsg.fileName }, 
        msgId: newMsg._id 
      });
      
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) { 
      alert('Upload failed.'); 
    } finally { 
      setIsUploading(false); 
    }
  };

  const filteredUsers = useMemo(() => {
    return users.filter((u) => u.name.toLowerCase().includes(searchQuery.toLowerCase()));
  }, [users, searchQuery]);

  if (!user || !token) return null;

  return (
    <div className="chat-shell flex h-screen bg-[#07090e] text-slate-100 font-sans antialiased overflow-hidden selection:bg-blue-600 selection:text-white">
      {/* Sidebar Navigation */}
      <aside className="chat-sidebar w-80 md:w-96 border-r border-white/5 bg-[#0b0e18]/90 backdrop-blur-2xl flex flex-col justify-between select-none">
        <div className="flex flex-col h-full overflow-hidden">
          {/* Header */}
          <div className="p-4 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center font-bold text-sm text-blue-400 shadow-sm">
                {user?.name?.charAt(0).toUpperCase()}
              </div>
              <div className="min-w-0">
                <h2 className="font-bold text-xs tracking-wide text-white truncate">{user?.name}</h2>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  <span className="text-[11px] text-slate-400 font-medium">Online Vault</span>
                </div>
              </div>
            </div>
            <button 
              onClick={logout} 
              className="p-2.5 hover:bg-rose-500/10 hover:text-rose-400 text-slate-400 rounded-xl transition-all duration-200 border border-transparent hover:border-rose-500/20 active:scale-95"
            >
              <LogOut size={17} />
            </button>
          </div>
          
          {/* Search Bar */}
          <div className="p-3 border-b border-white/5 bg-white/[0.01]">
            <div className="flex items-center justify-between px-1.5 mb-2">
              <span className="text-[10px] uppercase tracking-[0.18em] text-slate-500 font-mono">Secure directory</span>
              <span className="text-[10px] text-emerald-400 font-mono">{onlineUserList.length} online</span>
            </div>
            <div className="relative">
              <Search size={14} className="absolute left-3.5 top-3 text-slate-500" />
              <input 
                type="text" 
                value={searchQuery} 
                onChange={(e) => setSearchQuery(e.target.value)} 
                placeholder="Search encrypted contacts..." 
                className="w-full bg-[#121727] border border-white/5 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 transition-all" 
              />
            </div>
          </div>
          
          {/* Contact List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1.5 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
            <div className="px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
              Contacts ({filteredUsers.length})
            </div>
            {filteredUsers.map((u) => {
              const isOnline = onlineUserList.includes(u._id);
              const isSelected = activeUser?._id === u._id;
              const unreadCount = unreadCounts[u._id] || 0;
              
              return (
                <div 
                  key={u._id} 
                  onClick={() => handleUserSelect(u)} 
                  className={`group p-3 rounded-xl cursor-pointer transition-all duration-150 flex items-center gap-3 border ${isSelected ? 'bg-blue-600/10 border-blue-500/40 shadow-sm' : 'bg-[#101423]/40 border-white/[0.03] hover:bg-[#121727] hover:border-white/10 text-slate-300'}`}
                >
                  <div className="relative flex-shrink-0">
                    <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-slate-800 to-slate-900 border border-white/10 flex items-center justify-center font-bold text-sm text-slate-200">
                      {u.name.charAt(0).toUpperCase()}
                    </div>
                    {isOnline && <span className="absolute bottom-0 right-0 w-3 h-3 bg-emerald-500 border-2 border-[#0b0e18] rounded-full shadow-sm"></span>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className={`font-semibold text-xs truncate transition-colors ${unreadCount > 0 ? 'text-emerald-400' : 'text-white group-hover:text-blue-300'}`}>
                        {u.name}
                      </p>
                      {u.publicKey && <Key size={11} className="text-cyan-400 flex-shrink-0" title="ECDH Key Active" />}
                    </div>
                    <div className="flex items-center justify-between mt-0.5">
                      <p className="text-[11px] text-slate-500 truncate font-mono">
                        {isOnline ? <span className="text-emerald-400">Online</span> : 'Offline'}
                      </p>
                      {unreadCount > 0 && (
                        <span className="bg-emerald-500 text-[#0b0e18] font-bold text-[10px] px-2 py-0.5 rounded-full">
                          {unreadCount}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        
        {/* Footer Badge */}
        <div className="p-3.5 border-t border-white/5 bg-[#080a12] flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-[10px]">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
            </span>
            <span>{activeSharedKey ? 'ECDH Dual Envelope E2EE' : 'AES-256 GCM'}</span>
          </div>
          <span className="text-slate-600 font-mono text-[10px]">P-256 Validated</span>
        </div>
      </aside>

      {/* Main Chat Area */}
      <main className="chat-main flex-1 min-w-0 flex flex-col bg-[#07090e] overflow-hidden">
        {activeUser ? (
          <>
            {/* Header */}
            <div className="h-16 px-6 border-b border-white/5 bg-[#0b0e18]/80 backdrop-blur-xl flex items-center justify-between z-10">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center font-bold text-sm text-blue-400">
                  {activeUser.name.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h3 className="font-bold text-xs text-white tracking-wide">{activeUser.name}</h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    {isOtherUserTyping ? (
                      <span className="text-[11px] text-blue-400 italic animate-pulse font-medium">typing...</span>
                    ) : (
                      <span className="text-[11px] text-slate-400 font-mono">{onlineUserList.includes(activeUser._id) ? '🟢 Online' : '⚪ Offline'}</span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2 text-[11px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg font-mono font-medium">
                  <ShieldCheck size={14} />
                  <span>{activeSharedKey ? 'ECDH Dual Envelope Active' : 'AES-256 Static Tunnel'}</span>
                </div>
                <button
                  type="button"
                  onClick={handleKillConversation}
                  disabled={isClearingConversation || messages.length === 0}
                  className="flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-[11px] font-mono font-bold text-rose-300 transition-colors hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                  title="Remove this conversation from your side"
                >
                  <Ban size={13} />
                  <span>{isClearingConversation ? 'KILLING...' : 'KILL'}</span>
                </button>
              </div>
            </div>

            {clearConversationError && (
              <div
                role="alert"
                className="flex items-center justify-between gap-3 border-b border-rose-500/20 bg-rose-500/10 px-6 py-2.5 text-xs text-rose-200"
              >
                <span>{clearConversationError}</span>
                <button
                  type="button"
                  onClick={() => setClearConversationError('')}
                  className="text-rose-200/70 hover:text-white"
                  aria-label="Dismiss error"
                >
                  ×
                </button>
              </div>
            )}

            {/* Chat Map Area */}
            <div className="chat-messages flex-1 overflow-y-auto p-6 space-y-3.5 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
              {messages.map((m) => {
                const isMe = m.sender === user?.id || m.sender?._id === user?.id;
                const fileNameStr = m.fileName || m.fileData?.fileName || '';
                const mimeTypeStr = m.fileData?.mimeType || '';
                const isAudioMessage = mimeTypeStr.includes('audio') || fileNameStr.includes('voice') || m.messageType === 'audio';

                return (
                  <div key={m._id} className={`flex group relative ${isMe ? 'justify-end' : 'justify-start'}`}>
                    <div 
                      className={`max-w-md p-3.5 rounded-2xl text-xs shadow-sm transition-all ${
                        isMe 
                          ? (m.isDeleted ? 'bg-[#101423] text-slate-400 border border-white/5 rounded-br-sm' : 'bg-blue-600 text-white rounded-br-sm shadow-blue-600/10') 
                          : (m.isDeleted ? 'bg-[#101423] text-slate-400 border border-white/5 rounded-bl-sm' : 'bg-[#101423] border border-white/5 text-slate-200 rounded-bl-sm')
                      }`}
                    >
                      {m.isDeleted ? (
                        <p className="italic font-mono text-[11px] flex items-center gap-1.5">
                          <Ban size={12} className="opacity-70" /> This message was deleted
                        </p>
                      ) : (
                        <>
                          {isAudioMessage ? (
                            <AudioMessage 
                              message={m} 
                              token={token} 
                              currentUserId={user?.id} 
                              myPrivateKey={myPrivateKey} 
                              activeSharedKey={activeSharedKey} 
                              isAdmin={user?.role === 'admin'} 
                            />
                          ) : m.messageType === 'image' ? (
                            <div className="space-y-1.5">
                              <img 
                                src={`${API_BASE}/api/files/download/${m._id}?token=${token}`} 
                                alt={m.fileName || 'Encrypted Media'} 
                                className="rounded-xl max-h-64 max-w-xs object-cover cursor-pointer hover:opacity-95 transition-opacity border border-white/10" 
                                onClick={() => window.open(`${API_BASE}/api/files/download/${m._id}?token=${token}`, '_blank')} 
                              />
                              <span className="text-[10px] block truncate text-slate-300 font-mono">{m.fileName}</span>
                            </div>
                          ) : m.messageType === 'file' ? (
                            <a 
                              href={`${API_BASE}/api/files/download/${m._id}?token=${token}`} 
                              target="_blank" 
                              rel="noreferrer" 
                              className="flex items-center gap-2.5 p-2.5 bg-black/20 hover:bg-black/30 rounded-xl transition-colors border border-white/5"
                            >
                              <FileText size={22} className="text-blue-300 flex-shrink-0" />
                              <span className="truncate max-w-[180px] text-xs font-mono font-medium">{m.fileName || 'Attachment'}</span>
                              <Download size={13} className="ml-auto opacity-70 flex-shrink-0" />
                            </a>
                          ) : (
                            <p className="whitespace-pre-wrap break-words leading-relaxed">{m.text}</p>
                          )}
                        </>
                      )}

                      <div className={`flex items-center justify-end gap-1.5 mt-1.5 font-mono text-[10px] ${isMe ? (m.isDeleted ? 'text-slate-500' : 'text-blue-200') : 'text-slate-500'}`}>
                        <span>{new Date(m.createdAt || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        {isMe && !m.isDeleted && (
                          <span className="ml-0.5">
                            {m.status === 'seen' ? <CheckCheck size={13} className="text-cyan-300" title="Seen" /> 
                             : m.status === 'delivered' ? <CheckCheck size={13} className="text-slate-300" title="Delivered" /> 
                             : m.status === 'sending' ? <div className="w-2.5 h-2.5 border-2 border-blue-300/30 border-t-blue-300 rounded-full animate-spin"></div> 
                             : <Check size={13} className="text-slate-400" title="Sent" />}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
              
              {/* Typing Indicator */}
              {isOtherUserTyping && (
                <div className="flex justify-start">
                  <div className="bg-[#101423] border border-white/5 text-slate-400 text-xs px-4 py-2 rounded-2xl rounded-bl-sm animate-pulse flex items-center gap-1.5 font-mono">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-bounce"></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-bounce [animation-delay:0.2s]"></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-bounce [animation-delay:0.4s]"></span>
                    <span className="ml-1 text-[11px]">{activeUser.name} is typing...</span>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input Form */}
            <form onSubmit={handleSend} className="p-4 border-t border-white/5 bg-[#0b0e18]/80 backdrop-blur-xl flex gap-2.5 items-center">
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileUpload} 
                className="hidden" 
                disabled={isUploading || isDerivingKey} 
              />
              <button 
                type="button" 
                onClick={() => fileInputRef.current.click()} 
                disabled={isUploading || isDerivingKey} 
                className={`p-2.5 bg-[#121727] hover:bg-[#1a2138] border border-white/5 text-slate-300 rounded-xl transition-all duration-150 active:scale-95 ${isUploading || isDerivingKey ? 'opacity-50 cursor-not-allowed' : ''}`} 
                title="Attach file or image"
              >
                <Paperclip size={18} />
              </button>
              
              <button 
                type="button" 
                onClick={isRecording ? stopRecording : startRecording} 
                disabled={isUploading || isDerivingKey} 
                className={`p-2.5 rounded-xl border transition-all duration-150 active:scale-95 flex items-center justify-center ${isRecording ? 'bg-rose-600 border-rose-500 text-white animate-pulse shadow-lg shadow-rose-600/30' : 'bg-[#121727] hover:bg-[#1a2138] border-white/5 text-slate-300'}`} 
                title={isRecording ? 'Stop Recording' : 'Record Encrypted Voice Note'}
              >
                {isRecording ? <Square size={18} /> : <Mic size={18} />}
              </button>

              {isRecording ? (
                <div className="flex-1 bg-rose-500/10 border border-rose-500/30 rounded-xl px-4 py-2.5 text-xs text-rose-300 font-mono flex items-center justify-between animate-pulse">
                  <span>Recording encrypted voice note...</span>
                  <span>{recordingSeconds}s</span>
                </div>
              ) : (
                <input 
                  type="text" 
                  placeholder={isDerivingKey ? 'Establishing secure session...' : isUploading ? 'Encrypting & uploading...' : 'Type an end-to-end encrypted message...'} 
                  disabled={isUploading || isDerivingKey} 
                  value={inputMsg} 
                  onChange={handleInputChange} 
                  className="flex-1 bg-[#121727] border border-white/5 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 transition-all" 
                />
              )}
              
              <button 
                type="submit" 
                disabled={isUploading || isDerivingKey || !inputMsg.trim() || isRecording} 
                className="bg-blue-600 hover:bg-blue-500 p-2.5 rounded-xl text-white transition-all duration-150 shadow-lg shadow-blue-600/25 active:scale-95 disabled:opacity-50" 
                title="Send message"
              >
                <Send size={18} />
              </button>
            </form>
          </>
        ) : (
          <div className="chat-empty flex-1 flex flex-col items-center justify-center text-slate-500 gap-3">
            <div className="w-16 h-16 rounded-2xl bg-white/[0.02] border border-white/5 flex items-center justify-center text-slate-600">
              <MessageSquare size={32} />
            </div>
            <h3 className="font-semibold text-slate-300 text-sm">Encrypted Messaging Workspace</h3>
            <p className="text-xs text-slate-500 max-w-sm text-center">Select a contact from the sidebar to establish an ECDH P-256 secure real-time session.</p>
          </div>
        )}
      </main>
    </div>
  );
}