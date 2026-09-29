// client/src/pages/AdminDashboard.jsx
import React, { useState, useEffect, useContext, useMemo } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { AuthContext } from '../context/AuthContext';
import { 
  LogOut, 
  Lock, 
  FileText, 
  Download, 
  Eye, 
  Clock, 
  MessageSquare, 
  Users, 
  ShieldCheck, 
  UserPlus, 
  RefreshCw, 
  Search, 
  CheckCircle2, 
  AlertCircle, 
  ChevronRight, 
  Ban
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  decryptWithSessionKey,
  exportPrivateKey,
  exportPublicKey,
  generateUserKeyPair,
  importPrivateKey,
  importPublicKey,
  importPublicKeyFromPrivateJwk,
  unwrapKeyForUser,
  deriveSharedSecret // FIXED: Imported the correct derivation function
} from '../utils/cryptoClient';
import AudioMessage from '../components/AudioMessage';

export default function AdminDashboard() {
  const { token, logout, user } = useContext(AuthContext);
  const [activeTab, setActiveTab] = useState('chats'); 
                                                   
  const [conversations, setConversations] = useState([]);
  const [activeConv, setActiveConv] = useState(null);
  const [chatLogs, setChatLogs] = useState([]);

  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [messageSearchQuery, setMessageSearchQuery] = useState('');

  const [hasMore, setHasMore] = useState(false);
  const [cursor, setCursor] = useState(null);

  const [activityLogs, setActivityLogs] = useState([]);

  const [newUser, setNewUser] = useState({ name: '', email: '', password: '', role: 'user' });
  const [provisionStatus, setProvisionStatus] = useState(null);
  const [isSubmittingUser, setIsSubmittingUser] = useState(false);
  
  const [adminPrivateKey, setAdminPrivateKey] = useState(null);

  const navigate = useNavigate();

  useEffect(() => {
    if (!token || user?.role !== 'admin') {
      navigate('/');
      return;
    }
    fetchConversations();
    fetchActivityLogs();
  }, [token, user]);

  // Initialize Admin Crypto Key Pair (From cloud fallback if local empty)
  useEffect(() => {
    if (!token || !user?.id) return;

    const initializeAdminKey = async () => {
      try {
        const storageKey = `ecdh_priv_${user.id}`;
        let storedPrivateKey = localStorage.getItem(storageKey);

        // CLOUD RESTORE FALLBACK (Like we did in Chat.jsx)
        if (!storedPrivateKey) {
          try {
            const res = await axios.get('http://localhost:5000/api/auth/my-keys', {
              headers: { Authorization: `Bearer ${token}` } 
            });
            if (res.data?.privateKey) {
              storedPrivateKey = res.data.privateKey;
              localStorage.setItem(storageKey, storedPrivateKey);
            }
          } catch (e) {
            console.warn("Could not fetch admin keys from cloud");
          }
        }

        if (storedPrivateKey) {
          setAdminPrivateKey(await importPrivateKey(storedPrivateKey));
          const publicKeyObj = await importPublicKeyFromPrivateJwk(storedPrivateKey);
          await axios.put(
            'http://localhost:5000/api/auth/public-key',
            { publicKey: await exportPublicKey(publicKeyObj) },
            { headers: { Authorization: `Bearer ${token}` } }
          );
          return;
        }

        // Generate brand new key if literally first time
        const keyPair = await generateUserKeyPair();
        const privJwk = await exportPrivateKey(keyPair.privateKey);
        const pubJwk = await exportPublicKey(keyPair.publicKey);
        
        localStorage.setItem(storageKey, privJwk);
        
        // Save to DB and Update PubKey
        await axios.post(
          'http://localhost:5000/api/auth/sync-keys', 
          { publicKey: pubJwk, privateKey: privJwk }, 
          { headers: { Authorization: `Bearer ${token}` } }
        );

        await axios.put(
          'http://localhost:5000/api/auth/public-key',
          { publicKey: pubJwk },
          { headers: { Authorization: `Bearer ${token}` } }
        );
        
        setAdminPrivateKey(keyPair.privateKey);
      } catch (err) {
        console.error('Admin key init failed:', err);
      }
    };

    initializeAdminKey();
  }, [token, user?.id]);

  // ROBUST DECRYPT ENGINE FOR ADMIN (Matches Chat.jsx format perfectly)
  const decryptAdminMessage = async (msg) => {
    if (msg.isDeleted) {
      return { ...msg, text: 'This message was deleted' };
    }

    const targetPubKeyStr = msg.senderPublicKey || msg.sender?.publicKey;

    if (!adminPrivateKey || !msg.adminKeyWrap || !targetPubKeyStr) {
      return { ...msg, text: '[Legacy/Missing Admin Escrow Wrap]' };
    }

    try {
      const senderPublicKey = await importPublicKey(targetPubKeyStr);
      
      // FIXED: Used the exact derivation method to match Chat.jsx 
      const sharedKey = await deriveSharedSecret(adminPrivateKey, senderPublicKey);

      const sessionKey = await unwrapKeyForUser(msg.adminKeyWrap, sharedKey);
      
      if (sessionKey) {
        const plain = await decryptWithSessionKey(msg.encryptedText, msg.iv, msg.authTag, sessionKey);
        return { ...msg, text: plain };
      }
      
      throw new Error('Unwrap success but decrypt failed');
    } catch (err) {
      return { ...msg, text: '[Decryption Failed: Mismatched Key]' };
    }
  };

  useEffect(() => {
    if (!token || user?.role !== 'admin') return;

    const adminSocket = io('http://localhost:5000', { auth: { token } });
    adminSocket.emit('joinAdminMonitor');

    adminSocket.on('liveAdminFeed', (newMsg) => {
      if (activeConv && newMsg.conversationId === activeConv._id) {
        decryptAdminMessage(newMsg).then((message) => {
          setChatLogs((prev) => [...prev, message]);
        });
      }
      fetchConversations();
    });

    adminSocket.on('messageDeleted', ({ msgId, conversationId }) => {
      if (activeConv && conversationId === activeConv._id) {
        setChatLogs((prev) => prev.map((msg) => 
          msg._id === msgId 
            ? { ...msg, isDeleted: true, text: 'This message was deleted', fileData: null, messageType: 'text' } 
            : msg
        ));
      }
    });

    return () => adminSocket.disconnect();
  }, [token, activeConv, user, adminPrivateKey]);

  const fetchConversations = async () => {
    try {
      const res = await axios.get('http://localhost:5000/api/admin/conversations', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setConversations(res.data);
    } catch (err) {}
  };

  const fetchActivityLogs = async () => {
    try {
      const res = await axios.get('http://localhost:5000/api/admin/activity-logs', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setActivityLogs(res.data);
    } catch (err) {}
  };

  const loadConversationHistory = async (conv) => {
    setActiveConv(conv);
    setMessageSearchQuery('');
    try {
      const res = await axios.get(`http://localhost:5000/api/admin/conversation/${conv._id}?limit=30`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setChatLogs(await Promise.all(res.data.messages.map(decryptAdminMessage)));
      setHasMore(res.data.hasMore);
      setCursor(res.data.nextCursor);
    } catch (err) {}
  };

  const loadOlderMessages = async () => {
    if (!cursor || !activeConv) return;
    try {
      const res = await axios.get(
        `http://localhost:5000/api/admin/conversation/${activeConv._id}?before=${cursor}&limit=30`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const decOlder = await Promise.all(res.data.messages.map(decryptAdminMessage));
      setChatLogs((prev) => [...decOlder, ...prev]);
      setHasMore(res.data.hasMore);
      setCursor(res.data.nextCursor);
    } catch (err) {}
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setProvisionStatus(null);
    setIsSubmittingUser(true);

    try {
      const res = await axios.post('http://localhost:5000/api/admin/create-user', newUser, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setProvisionStatus({ type: 'success', message: `Account for "${res.data.user.name}" created successfully!` });
      setNewUser({ name: '', email: '', password: '', role: 'user' });
      fetchConversations();
    } catch (err) {
      setProvisionStatus({ type: 'error', message: err.response?.data?.error || 'Failed to create user account.' });
    } finally {
      setIsSubmittingUser(false);
    }
  };

  const filteredConversations = useMemo(() => {
    if (!userSearchQuery.trim()) return conversations;
    const query = userSearchQuery.toLowerCase();
    return conversations.filter((conv) => {
      const u1Name = conv.user1?.name?.toLowerCase() || '';
      const u1Email = conv.user1?.email?.toLowerCase() || '';
      const u2Name = conv.user2?.name?.toLowerCase() || '';
      const u2Email = conv.user2?.email?.toLowerCase() || '';
      return (
        u1Name.includes(query) || u1Email.includes(query) || u2Name.includes(query) || u2Email.includes(query)
      );
    });
  }, [conversations, userSearchQuery]);

  const filteredChatLogs = useMemo(() => {
    if (!messageSearchQuery.trim()) return chatLogs;
    const query = messageSearchQuery.toLowerCase();
    return chatLogs.filter((log) => {
      const textMatch = log.text?.toLowerCase().includes(query);
      const senderMatch = log.sender?.name?.toLowerCase().includes(query);
      const fileMatch = log.fileName?.toLowerCase().includes(query);
      return textMatch || senderMatch || fileMatch;
    });
  }, [chatLogs, messageSearchQuery]);

  const formatDuration = (seconds) => {
    if (!seconds || seconds <= 0) return 'Just left';
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const remainingSecs = seconds % 60;
    return `${mins}m ${remainingSecs}s`;
  };

  if (!user || !token) return null;

  return (
    <div className="admin-shell flex h-screen bg-[#07090e] text-slate-100 font-sans antialiased overflow-hidden selection:bg-blue-600 selection:text-white">
      {/* Sidebar Navigation */}
      <aside className="admin-sidebar w-80 md:w-96 border-r border-white/5 bg-[#0b0e18]/90 backdrop-blur-2xl flex flex-col justify-between select-none z-20">
        <div className="flex flex-col h-full overflow-hidden">
          {/* Header */}
          <div className="p-4 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.15)]">
                <ShieldCheck size={22} />
              </div>
              <div>
                <h1 className="font-bold text-sm tracking-wide text-white flex items-center gap-1.5">
                  Admin Audit Hub
                </h1>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  <span className="text-[11px] text-slate-400 font-medium tracking-tight">Monitoring Node Active</span>
                </div>
              </div>
            </div>
            <button 
              onClick={logout} 
              className="p-2.5 hover:bg-rose-500/10 hover:text-rose-400 text-slate-400 rounded-xl transition-all duration-200 border border-transparent hover:border-rose-500/20 active:scale-95"
              title="Sign Out"
            >
              <LogOut size={17} />
            </button>
          </div>

          {/* Navigation Tabs */}
          <div className="p-3">
            <div className="flex items-center justify-between px-1.5 mb-2">
              <span className="text-[10px] uppercase tracking-[0.18em] text-slate-500 font-mono">Operations center</span>
              <span className="text-[10px] text-emerald-400 font-mono">Live</span>
            </div>
            <div className="grid grid-cols-3 gap-1 bg-[#121727] p-1 rounded-xl border border-white/5">
              <button
                onClick={() => setActiveTab('chats')}
                className={`flex items-center justify-center gap-2 py-2 px-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
                  activeTab === 'chats' 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                }`}
              >
                <MessageSquare size={14} />
                <span>Chats</span>
              </button>

              <button
                onClick={() => { setActiveTab('activity'); fetchActivityLogs(); }}
                className={`flex items-center justify-center gap-2 py-2 px-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
                  activeTab === 'activity' 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                }`}
              >
                <Clock size={14} />
                <span>Sessions</span>
              </button>

              <button
                onClick={() => { setActiveTab('createUser'); setProvisionStatus(null); }}
                className={`flex items-center justify-center gap-2 py-2 px-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
                  activeTab === 'createUser' 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                }`}
              >
                <UserPlus size={14} />
                <span>Add User</span>
              </button>
            </div>
          </div>

          {/* Active Chats Sidebar View */}
          {activeTab === 'chats' && (
            <div className="flex-1 flex flex-col overflow-hidden px-3">
              <div className="mb-2">
                <div className="relative">
                  <Search size={14} className="absolute left-3.5 top-3 text-slate-500" />
                  <input
                    type="text"
                    value={userSearchQuery}
                    onChange={(e) => setUserSearchQuery(e.target.value)}
                    placeholder="Search by user name or email..."
                    className="w-full bg-[#121727]/80 border border-white/5 rounded-xl pl-9 pr-8 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 transition-all"
                  />
                  {userSearchQuery && (
                    <button 
                      onClick={() => setUserSearchQuery('')}
                      className="absolute right-3 top-2 text-xs text-slate-400 hover:text-white transition"
                    >
                      ×
                    </button>
                  )}
                </div>
              </div>

              <div className="flex-1 overflow-y-auto space-y-1.5 pr-0.5 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
                <div className="flex items-center justify-between px-2 py-1">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
                    Conversations ({filteredConversations.length})
                  </span>
                </div>

                {filteredConversations.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No matching users or conversations found.
                  </div>
                ) : (
                  filteredConversations.map((conv) => {
                    const isSelected = activeConv?._id === conv._id;
                    return (
                      <div
                        key={conv._id}
                        onClick={() => loadConversationHistory(conv)}
                        className={`group p-3 rounded-xl cursor-pointer transition-all duration-150 flex items-center gap-3 border ${
                          isSelected 
                            ? 'bg-blue-600/10 border-blue-500/40 shadow-sm' 
                            : 'bg-[#101423]/40 border-white/[0.03] hover:bg-[#121727] hover:border-white/10 text-slate-300'
                        }`}
                      >
                        <div className="relative flex-shrink-0">
                          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-slate-800 to-slate-900 border border-white/10 flex items-center justify-center font-bold text-xs text-slate-200">
                            {conv.user1?.name?.charAt(0) || 'U'}
                          </div>
                          <div className="w-5 h-5 rounded-full bg-blue-600 border-2 border-[#0b0e18] flex items-center justify-center font-bold text-[9px] text-white absolute -bottom-1 -right-1 shadow-sm">
                            {conv.user2?.name?.charAt(0) || 'U'}
                          </div>
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-0.5">
                            <p className="font-semibold text-xs text-white truncate group-hover:text-blue-300 transition-colors">
                              {conv.user1?.name} & {conv.user2?.name}
                            </p>
                            <span className="text-[10px] text-slate-500 font-mono ml-2 flex-shrink-0">
                              {new Date(conv.lastMessageAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                            </span>
                          </div>
                          <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span className="truncate">
                              <span className="text-blue-400 font-medium">{conv.totalMessages}</span> messages recorded
                            </span>
                            <ChevronRight size={12} className={`transition-all ${isSelected ? 'text-blue-400 translate-x-0.5' : 'opacity-0 group-hover:opacity-100 text-slate-500'}`} />
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {activeTab !== 'chats' && (
            <div className="flex-1 p-6 flex flex-col items-center justify-center text-center text-slate-500">
              <div className="w-12 h-12 rounded-2xl bg-white/[0.02] border border-white/5 flex items-center justify-center text-slate-600 mb-3">
                <Users size={24} />
              </div>
              <p className="text-xs font-medium text-slate-400">Real-Time Audit Node</p>
              <p className="text-[11px] text-slate-600 mt-1 max-w-[200px]">Switch to Chats tab to view encrypted thread traffic.</p>
            </div>
          )}
        </div>

        {/* Master Security Status */}
        <div className="p-3.5 border-t border-white/5 bg-[#080a12] flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-[10px]">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
            </span>
            <span>AES-256 GCM Live</span>
          </div>
          <span className="text-slate-600 font-mono text-[10px]">v2.4 Audit Console</span>
        </div>
      </aside>

      {/* Main Window */}
      <main className="admin-main flex-1 min-w-0 flex flex-col bg-[#07090e] overflow-hidden relative">
        {activeTab === 'chats' ? (
          activeConv ? (
            <>
              {/* Active Conversation Top Bar */}
              <div className="h-16 px-6 border-b border-white/5 bg-[#0b0e18]/80 backdrop-blur-xl flex justify-between items-center z-10">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 flex-shrink-0">
                    <Users size={18} />
                  </div>
                  <div className="min-w-0">
                    <h2 className="text-xs font-semibold text-white flex items-center gap-2 truncate">
                      <span>{activeConv.user1?.name}</span>
                      <span className="text-slate-500 font-mono">↔</span>
                      <span>{activeConv.user2?.name}</span>
                    </h2>
                    <p className="text-[10px] text-slate-500 font-mono truncate mt-0.5">Thread ID: {activeConv._id}</p>
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  {/* In-chat Message Search Bar */}
                  <div className="relative w-56 md:w-64">
                    <Search size={13} className="absolute left-3 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      value={messageSearchQuery}
                      onChange={(e) => setMessageSearchQuery(e.target.value)}
                      placeholder="Search in conversation..."
                      className="w-full bg-[#121727] border border-white/5 rounded-lg pl-8 pr-7 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 transition-all"
                    />
                    {messageSearchQuery && (
                      <button 
                        onClick={() => setMessageSearchQuery('')}
                        className="absolute right-2.5 top-2 text-xs text-slate-400 hover:text-white transition"
                      >
                        ×
                      </button>
                    )}
                  </div>

                  <span className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[11px] px-3 py-1.5 rounded-lg flex items-center gap-1.5 font-mono font-medium">
                    <Lock size={12} /> Decrypted Output
                  </span>
                </div>
              </div>

              {/* Chat Stream */}
              <div className="flex-1 overflow-y-auto p-6 space-y-3.5 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent relative z-10">
                {hasMore && (
                  <div className="text-center pb-2">
                    <button
                      onClick={loadOlderMessages}
                      className="text-xs bg-white/[0.03] hover:bg-white/[0.06] text-blue-400 px-4 py-1.5 rounded-full border border-white/10 transition-all shadow-sm active:scale-95"
                    >
                      Load Older Messages
                    </button>
                  </div>
                )}

                {filteredChatLogs.length === 0 ? (
                  <div className="py-24 text-center text-slate-500 text-xs">
                    {messageSearchQuery ? 'No messages match your search query.' : 'No messages in this conversation yet.'}
                  </div>
                ) : (
                  filteredChatLogs.map((log) => {
                    const isAudioMessage = log.fileName?.includes('voice') || log.fileData?.mimeType?.includes('audio') || log.fileData?.fileName?.includes('voice');

                    return (
                      <div key={log._id} className="bg-[#0e1220] border border-white/5 p-4 rounded-2xl max-w-2xl shadow-sm hover:border-white/10 transition-colors">
                        <div className="flex justify-between items-center mb-2 pb-1.5 border-b border-white/[0.04]">
                          <span className="text-xs font-semibold text-blue-400 flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                            {log.sender?.name} <span className="text-slate-500 font-normal">({log.sender?.email})</span>
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {new Date(log.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {new Date(log.createdAt).toLocaleDateString()}
                          </span>
                        </div>

                        {/* RENDER LOGIC */}
                        {log.isDeleted ? (
                          <p className="italic font-mono text-[11px] flex items-center gap-1.5 text-slate-500 mt-1">
                            <Ban size={12} className="opacity-70" /> This message was deleted by the sender
                          </p>
                        ) : isAudioMessage ? (
                          <div className="mt-1">
                            <AudioMessage
                              message={log}
                              token={token}
                              currentUserId={user.id}
                              myPrivateKey={adminPrivateKey}
                              activeSharedKey={null}
                              isAdmin={true}
                            />
                          </div>
                        ) : log.messageType === 'image' ? (
                          <div className="space-y-2 pt-1">
                            <img
                              src={`http://localhost:5000/api/files/download/${log._id}?token=${token}`}
                              alt={log.fileName}
                              className="max-h-72 rounded-xl border border-white/5 object-cover cursor-pointer hover:opacity-95 transition-opacity"
                              onClick={() => window.open(`http://localhost:5000/api/files/download/${log._id}?token=${token}`, '_blank')}
                            />
                            <p className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                              <Eye size={11} /> {log.fileName}
                            </p>
                          </div>
                        ) : log.messageType === 'file' ? (
                          <div className="flex items-center justify-between p-3 bg-[#080a12] rounded-xl border border-white/5">
                            <div className="flex items-center gap-2.5 min-w-0 pr-2">
                              <FileText size={18} className="text-blue-400 flex-shrink-0" />
                              <span className="text-xs font-mono text-slate-300 truncate">{log.fileName}</span>
                            </div>
                            <a
                              href={`http://localhost:5000/api/files/download/${log._id}?token=${token}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-xs bg-blue-500/10 hover:bg-blue-600 text-blue-400 hover:text-white px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors flex-shrink-0 border border-blue-500/20"
                            >
                              <Download size={12} /> Download
                            </a>
                          </div>
                        ) : (
                          <p className="text-xs text-slate-200 bg-[#080a12] p-3 rounded-xl border border-white/[0.04] leading-relaxed font-normal">
                            {log.text}
                          </p>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </>
          ) : (
            // ===============================================
            // ENHANCED ADMIN EMPTY STATE (CYBER RADAR UI)
            // ===============================================
            <div className="flex-1 flex flex-col items-center justify-center relative overflow-hidden bg-[#07090e]">
              {/* Subtle Matrix/Dotted Background */}
              <div 
                className="absolute inset-0 opacity-[0.03] pointer-events-none" 
                style={{ backgroundImage: 'radial-gradient(#fff 1px, transparent 1px)', backgroundSize: '24px 24px' }}
              ></div>
              
              {/* Glowing Shield Radar Effect */}
              <div className="relative z-10 flex flex-col items-center gap-5">
                <div className="relative flex items-center justify-center w-24 h-24">
                  <div className="absolute inset-0 rounded-full border-2 border-blue-500/20 animate-[ping_3s_ease-in-out_infinite]"></div>
                  <div className="absolute inset-2 rounded-full border border-blue-500/30 animate-[ping_2s_ease-in-out_infinite_0.5s]"></div>
                  
                  <div className="relative z-10 w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-900/40 to-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-[0_0_30px_rgba(59,130,246,0.2)] backdrop-blur-xl">
                    <ShieldCheck size={32} />
                  </div>
                </div>

                <div className="text-center mt-2">
                  <h3 className="font-bold text-slate-200 text-sm tracking-widest mb-2 uppercase">Secure Audit Terminal</h3>
                  <p className="text-[11px] text-slate-500 max-w-[280px] leading-relaxed font-mono">
                    Awaiting target selection.<br/> 
                    Click on any encrypted thread from the directory to initialize decryption sequence.
                  </p>
                </div>
              </div>
            </div>
          )
        ) : activeTab === 'activity' ? (
          /* User Activity / Duration Tracker Tab */
            <div className="admin-content flex-1 flex flex-col p-8 overflow-y-auto">
            <div className="mb-6 flex justify-between items-center">
              <div>
                <h2 className="text-base font-bold text-white tracking-wide">Active Sessions & Duration Audit</h2>
                <p className="text-xs text-slate-400 mt-0.5">Real-time log of when users connect, disconnect, and total duration spent online.</p>
              </div>
              <button 
                onClick={fetchActivityLogs}
                className="text-xs bg-[#121727] hover:bg-[#1a2138] border border-white/10 px-3.5 py-2 rounded-xl text-slate-200 transition-colors flex items-center gap-2 shadow-sm"
              >
                <RefreshCw size={12} />
                <span>Refresh Log</span>
              </button>
            </div>

            <div className="bg-[#0b0e18] border border-white/5 rounded-2xl overflow-hidden shadow-xl">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider bg-white/[0.02]">
                    <th className="p-4 pl-5">User</th>
                    <th className="p-4">Status</th>
                    <th className="p-4">Logged In At</th>
                    <th className="p-4">Disconnected At</th>
                    <th className="p-4 pr-5">Total Online Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.03] text-xs">
                  {activityLogs.map((log) => (
                    <tr key={log._id} className="hover:bg-white/[0.01] transition-colors">
                      <td className="p-4 pl-5">
                        <p className="font-semibold text-white">{log.userId?.name || 'Unknown'}</p>
                        <p className="text-[11px] text-slate-500 font-mono">{log.userId?.email}</p>
                      </td>
                      <td className="p-4">
                        {log.status === 'online' ? (
                          <span className="inline-flex items-center gap-1.5 bg-emerald-500/10 text-emerald-400 px-2.5 py-1 rounded-full text-[10px] font-medium border border-emerald-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            Online Now
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[11px] font-mono">Logged Out</span>
                        )}
                      </td>
                      <td className="p-4 text-slate-300 font-mono text-[11px]">
                        {new Date(log.loginAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' })}
                      </td>
                      <td className="p-4 text-slate-300 font-mono text-[11px]">
                        {log.logoutAt 
                          ? new Date(log.logoutAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' }) 
                          : '—'}
                      </td>
                      <td className="p-4 pr-5 font-semibold text-blue-400 font-mono text-[11px]">
                        {log.status === 'online' ? 'Active Session' : formatDuration(log.durationSeconds)}
                      </td>
                    </tr>
                  ))}
                  {activityLogs.length === 0 && (
                    <tr>
                      <td colSpan="5" className="p-8 text-center text-slate-500">
                        No activity records logged yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          /* Create User Account Tab */
          <div className="admin-content flex-1 flex flex-col items-center justify-center p-8 overflow-y-auto">
            <div className="w-full max-w-md bg-[#0b0e18] border border-white/5 rounded-2xl p-7 shadow-2xl">
              <div className="flex items-center gap-3.5 mb-5 pb-4 border-b border-white/5">
                <div className="w-11 h-11 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center">
                  <UserPlus size={20} />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">Create New User Account</h2>
                  <p className="text-xs text-slate-400 mt-0.5">Assign credentials for internal platform access.</p>
                </div>
              </div>

              {provisionStatus && (
                <div className={`mb-5 p-3 rounded-xl text-xs flex items-center gap-2 border ${
                  provisionStatus.type === 'success' 
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                    : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                }`}>
                  {provisionStatus.type === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                  <span>{provisionStatus.message}</span>
                </div>
              )}

              <form onSubmit={handleCreateUser} className="space-y-4">
                <div>
                  <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">Full Name</label>
                  <input
                    type="text"
                    required
                    value={newUser.name}
                    onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
                    placeholder="e.g. Sahil Raja"
                    className="w-full bg-[#121727] border border-white/5 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">Assigned Email</label>
                  <input
                    type="email"
                    required
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    placeholder="user@internal.io"
                    className="w-full bg-[#121727] border border-white/5 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">Account Password</label>
                  <input
                    type="password"
                    required
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    placeholder="••••••••"
                    className="w-full bg-[#121727] border border-white/5 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">Role Permission</label>
                  <select
                    value={newUser.role}
                    onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                    className="w-full bg-[#121727] border border-white/5 rounded-xl px-3 py-2.5 text-xs text-white focus:outline-none focus:border-blue-500/50 transition-all cursor-pointer"
                  >
                    <option value="user">Standard User</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={isSubmittingUser}
                  className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-xl text-xs transition-all mt-2 shadow-lg shadow-blue-600/20 disabled:opacity-50 active:scale-[0.99]"
                >
                  {isSubmittingUser ? 'Registering Account...' : 'Create Account'}
                </button>
              </form>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}