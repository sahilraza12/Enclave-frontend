import React, { useState, useContext } from 'react';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Check, KeyRound, LockKeyhole, ShieldCheck } from 'lucide-react';

export default function Auth() {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({ name: '', email: '', password: '', role: 'user' });
  const [error, setError] = useState('');
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  // Dynamic API Base URL (Deployed backend ba Localhost fallback)
  const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';

    try {
      // Hardcoded localhost er jaygay dynamic API_BASE use kora hoyeche
      const res = await axios.post(`${API_BASE}${endpoint}`, formData);
      
      if (isLogin) {
        login(res.data.user, res.data.token);
        if (res.data.user.role === 'admin') {
          navigate('/admin');
        } else {
          navigate('/chat');
        }
      } else {
        setIsLogin(true);
        alert('Registered successfully! Please login.');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Something went wrong');
    }
  };

  return (
    <main className="auth-shell">
      <section className="auth-intro">
        <div className="intro-grid" />
        <div className="brand-mark"><LockKeyhole size={18} /></div>
        <p className="eyebrow">CHAR / PRIVATE NETWORK</p>
        <div className="intro-copy">
          <h1>Conversations,<br /><em>kept yours.</em></h1>
          <p>Private communication for teams that value clarity, control, and a quieter digital workspace.</p>
        </div>
        <div className="trust-row">
          <div className="trust-icon"><ShieldCheck size={18} /></div>
          <div><strong>End-to-end protected</strong><span>Your messages stay yours.</span></div>
        </div>
        <div className="intro-footer"><span>EST. 2024</span><span className="footer-line" /><span>SECURE BY DEFAULT</span></div>
      </section>
      <section className="auth-panel">
        <div className="auth-panel-inner">
          <div className="mobile-brand"><div className="brand-mark"><LockKeyhole size={18} /></div><span>CHAR</span></div>
          <div className="form-heading">
            <span className="form-kicker">WELCOME BACK</span>
            <h2>{isLogin ? 'Enter your space.' : 'Make it yours.'}</h2>
            <p>{isLogin ? 'Sign in to continue the conversation.' : 'Create your secure account in a moment.'}</p>
          </div>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <form onSubmit={handleSubmit} className="auth-form">
          {!isLogin && (
            <>
              <div className="field">
                <label htmlFor="name">Name</label>
                <input
                  id="name"
                  type="text"
                  required
                  placeholder="Your name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>
              <div className="field">
                <label htmlFor="role">Account type</label>
                <select
                  id="role"
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                >
                  <option value="user">Normal User (Encrypted Chat)</option>
                  <option value="admin">Admin (Auditor / Decrypt Access)</option>
                </select>
              </div>
            </>
          )}

          <div className="field">
            <label htmlFor="email">Email address</label>
            <input
              id="email"
              type="email"
              required
              placeholder="you@company.com"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            />
          </div>

          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              required
              placeholder="Enter your password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            />
          </div>

          <button type="submit" className="submit-button">
            <span>{isLogin ? 'Enter workspace' : 'Create account'}</span><ArrowRight size={18} />
          </button>
        </form>

          <button type="button" className="switch-button" onClick={() => setIsLogin(!isLogin)}>
            {isLogin ? <><span>New to Char?</span> Create an account</> : <><span>Already a member?</span> Sign in</>}
          </button>
          <div className="form-note"><KeyRound size={14} /><span>Protected connection <Check size={14} /></span></div>
        </div>
      </section>
    </main>
  );
}