// client/src/components/AudioMessage.jsx
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Play, Pause, Loader } from 'lucide-react';
import { 
  unwrapKeyForUser, 
  decryptAudioBytes, 
  importPublicKey, 
  deriveSharedSecret 
} from '../utils/cryptoClient';

export default function AudioMessage({ 
  message, 
  token, 
  currentUserId, 
  myPrivateKey, 
  activeSharedKey, 
  isAdmin 
}) {
  const [audioUrl, setAudioUrl] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const audioRef = useRef(null);

  // Component unmount hone par memory cleanup
  useEffect(() => {
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
      }
      if (audioUrl) {
        URL.revokeObjectURL(audioUrl);
      }
    };
  }, [audioUrl]);

  const loadAndPlayAudio = async () => {
    // Agar already decrypted audio present hai toh toggle play/pause
    if (audioUrl && audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause();
        setIsPlaying(false);
      } else {
        audioRef.current.play();
        setIsPlaying(true);
      }
      return;
    }

    setLoading(true);
    try {
      // 1. Fetch raw encrypted ciphertext bytes from server
      const res = await axios.get(`http://localhost:5000/api/files/audio/${message._id}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'arraybuffer'
      });

      // 2. Resolve Key Wrap & Shared Secret
      let keyToUnwrap = message.recipientKeyWrap;
      let sharedSecret = activeSharedKey;

      const isSender = 
        String(message.sender) === currentUserId || 
        String(message.sender?._id) === currentUserId;

      if (isSender && message.senderKeyWrap) {
        keyToUnwrap = message.senderKeyWrap;
      }

      // 3. Admin Escrow Audit Decryption Flow
      if (isAdmin && message.adminKeyWrap && myPrivateKey) {
        keyToUnwrap = message.adminKeyWrap;

        let senderPubKeyStr = message.senderPublicKey || message.sender?.publicKey;

        // Agar socket payload me public key missing ho toh server se fetch karein
        if (!senderPubKeyStr) {
          const senderId = message.sender?._id || message.sender;
          const userRes = await axios.get('http://localhost:5000/api/auth/users', {
            headers: { Authorization: `Bearer ${token}` }
          });
          const targetSender = userRes.data.find(u => u._id === senderId);
          senderPubKeyStr = targetSender?.publicKey;
        }

        if (senderPubKeyStr) {
          const senderPub = await importPublicKey(senderPubKeyStr);
          sharedSecret = await deriveSharedSecret(myPrivateKey, senderPub);
        }
      }

      if (!keyToUnwrap || !sharedSecret) {
        throw new Error('Required cryptographic keys are unavailable');
      }

      // 4. Unwrap session key and decrypt audio buffer
      const sessionKey = await unwrapKeyForUser(keyToUnwrap, sharedSecret);
      if (!sessionKey) throw new Error('Session key unwrap rejected');

      const url = await decryptAudioBytes(res.data, message.iv, message.authTag, sessionKey);
      
      const audio = new Audio(url);
      audio.onended = () => setIsPlaying(false);
      audio.onerror = () => {
        setIsPlaying(false);
        console.error('Audio playback error');
      };

      audioRef.current = audio;
      setAudioUrl(url);

      await audio.play();
      setIsPlaying(true);

    } catch (err) {
      console.error('Audio decryption failed:', err);
      alert('Unable to decrypt voice recording. Key mismatch or unauthorized.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center gap-3 p-2.5 bg-black/20 hover:bg-black/30 rounded-xl transition-all border border-white/5 min-w-[210px] select-none">
      <button
        type="button"
        onClick={loadAndPlayAudio}
        disabled={loading}
        className="w-8 h-8 rounded-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 flex items-center justify-center text-white transition-all shadow-md active:scale-95 flex-shrink-0"
        title={isPlaying ? 'Pause voice message' : 'Play voice message'}
      >
        {loading ? (
          <Loader size={14} className="animate-spin text-white" />
        ) : isPlaying ? (
          <Pause size={14} />
        ) : (
          <Play size={14} className="ml-0.5" />
        )}
      </button>

      <div className="flex flex-col min-w-0">
        <span className="text-[11px] font-mono font-medium text-slate-200 truncate">
          {isAdmin ? 'Admin Audit Voice' : 'Encrypted Voice Note'}
        </span>
        <span className="text-[9px] text-slate-400 font-mono">
          {loading ? 'Decrypting payload...' : isPlaying ? 'Playing note...' : 'Tap to decrypt & play'}
        </span>
      </div>
    </div>
  );
}