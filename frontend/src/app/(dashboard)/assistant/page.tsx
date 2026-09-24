"use client";

import { API_URL, WS_URL } from "@/lib/api";

import { useState, useRef, useEffect } from "react";
import { Bot, User, Send, Loader2, Sparkles, Shield, Terminal, Copy, Check } from "lucide-react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  engine?: string;
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      role: "assistant",
      content: "Hello! I am **SentinelX AI**, your security operations and CSPM copilot.\n\nI can analyze your active findings, explain threat detections, and generate Terraform or AWS CLI remediation commands.",
      engine: "SentinelX Security Copilot"
    }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [keyStatus, setKeyStatus] = useState<{ configured: boolean; prefix?: string } | null>(null);

  useEffect(() => {
    fetch(`${API_URL}/api/assistant/status`)
      .then(res => res.json())
      .then(data => {
        setKeyStatus({
          configured: !!data.gemini_api_key_configured,
          prefix: data.key_prefix
        });
      })
      .catch(() => setKeyStatus({ configured: false }));
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };


  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const sendPrompt = async (promptText: string) => {
    if (!promptText.trim() || isLoading) return;

    const userMsg: Message = { id: Date.now().toString(), role: "user", content: promptText };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/assistant/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: promptText }),
      });
      const data = await response.json();
      
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.response || "No response received.",
        engine: data.engine
      }]);
    } catch (error) {
      console.error(error);
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "⚠️ Failed to communicate with SentinelX AI assistant API backend."
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendPrompt(input);
  };

  const quickPrompts = [
    { label: "S3 Bucket Exposure", query: "Why is public S3 risky and how do I fix it?" },
    { label: "SSH Brute Force", query: "Analyze the SSH brute force threat on port 22" },
    { label: "Environment Briefing", query: "Give me a summary of current alerts and active findings" },
    { label: "Terraform Remediation", query: "Generate Terraform code to enforce S3 bucket public access block" }
  ];

  const renderMessageContent = (content: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);
    
    return parts.map((part, index) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const lines = part.split('\n');
        const lang = lines[0].replace('```', '').trim() || 'code';
        const code = lines.slice(1, -1).join('\n');
        
        return (
          <div key={index} className="my-3 rounded-lg overflow-hidden border border-gray-800 bg-[#0d1117] text-gray-200">
            <div className="flex items-center justify-between px-3 py-1.5 bg-[#161b22] border-b border-gray-800 text-xs font-mono text-gray-400">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                {lang}
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(code, index)}
                className="flex items-center gap-1 hover:text-white transition-colors"
              >
                {copiedIndex === index ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 text-xs md:text-sm font-mono overflow-x-auto leading-relaxed text-emerald-300">
              <code>{code}</code>
            </pre>
          </div>
        );
      }
      
      const formattedText = part
        .split('\n')
        .map((line, i) => {
          if (!line.trim()) return <div key={`empty-${i}`} className="h-2" />;
          
          if (line.startsWith('### ')) {
            return (
              <h3 key={`h3-${i}`} className="text-base font-bold text-gray-900 mt-2 mb-1 flex items-center gap-1.5">
                {line.replace('### ', '')}
              </h3>
            );
          }
          if (line.startsWith('#### ')) {
            return (
              <h4 key={`h4-${i}`} className="text-sm font-semibold text-gray-800 mt-2 mb-1">
                {line.replace('#### ', '')}
              </h4>
            );
          }

          const boldedLine = line.split(/(\*\*.*?\*\*)/g).map((segment, j) => {
            if (segment.startsWith('**') && segment.endsWith('**')) {
              return <strong key={`bold-${j}`} className="font-semibold text-gray-900">{segment.slice(2, -2)}</strong>;
            }
            return <span key={`text-${j}`}>{segment}</span>;
          });

          return (
            <p key={`p-${i}`} className="mb-1.5 text-sm leading-relaxed text-gray-700">
              {boldedLine}
            </p>
          );
        });

      return <div key={index}>{formattedText}</div>;
    });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] max-w-5xl mx-auto bg-surface border border-sentinel rounded-xl shadow-sm overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-border bg-gradient-to-r from-gray-50 via-white to-gray-50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary/10 border border-primary/20 rounded-lg flex items-center justify-center">
            <Bot className="w-5 h-5 text-primary" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-foreground">SentinelX AI Copilot</h1>
              <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                Connected
              </span>
            </div>
            <p className="text-xs text-muted">
              Intelligent telemetry analysis, threat triage & automated remediation drafting
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {keyStatus !== null && (
            <div className={`flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md border ${
              keyStatus.configured 
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                : 'bg-amber-50 text-amber-800 border-amber-300'
            }`}>
              <Sparkles className={`w-3.5 h-3.5 ${keyStatus.configured ? 'text-emerald-600' : 'text-amber-600'}`} />
              <span>{keyStatus.configured ? `Gemini Live Active (${keyStatus.prefix})` : 'Gemini Key Missing on Backend'}</span>
            </div>
          )}
          <div className="hidden sm:flex items-center gap-2 text-xs text-muted bg-surface border border-border rounded-md px-3 py-1.5">
            <Shield className="w-3.5 h-3.5 text-primary" />
            <span>Telemetry Context Active</span>
          </div>
        </div>
      </div>


      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-gray-50/50">
        {messages.map((msg) => (
          <div key={msg.id} className={`flex gap-3.5 ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
            <div className={`w-8 h-8 shrink-0 rounded-full flex items-center justify-center shadow-xs ${
              msg.role === 'user' ? 'bg-gray-800 text-white' : 'bg-primary text-white'
            }`}>
              {msg.role === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
            </div>
            
            <div className={`max-w-[85%] rounded-2xl px-5 py-4 shadow-xs ${
              msg.role === 'user' 
                ? 'bg-primary text-white rounded-tr-none' 
                : 'bg-white border border-gray-200/90 text-gray-800 rounded-tl-none'
            }`}>
              {renderMessageContent(msg.content)}
              {msg.engine && (
                <div className="mt-2 pt-2 border-t border-gray-100 flex items-center gap-1 text-[11px] text-muted">
                  <Sparkles className="w-3 h-3 text-amber-500" />
                  <span>Powered by {msg.engine}</span>
                </div>
              )}
            </div>
          </div>
        ))}
        
        {isLoading && (
          <div className="flex gap-3.5 flex-row">
            <div className="w-8 h-8 shrink-0 rounded-full flex items-center justify-center bg-primary text-white">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl rounded-tl-none px-5 py-3 shadow-xs flex items-center gap-2.5">
              <Loader2 className="w-4 h-4 text-primary animate-spin" />
              <span className="text-xs font-medium text-muted">Analyzing telemetry & generating recommendations...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-4 py-2 bg-white border-t border-border flex items-center gap-2 overflow-x-auto text-xs">
        <span className="text-muted shrink-0 flex items-center gap-1 font-medium">
          <Sparkles className="w-3.5 h-3.5 text-primary" /> Quick actions:
        </span>
        {quickPrompts.map((qp, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => sendPrompt(qp.query)}
            disabled={isLoading}
            className="shrink-0 px-2.5 py-1 rounded-md bg-gray-100 hover:bg-gray-200 text-gray-700 transition-colors border border-gray-200"
          >
            {qp.label}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <div className="p-4 bg-white border-t border-border">
        <form onSubmit={handleSubmit} className="flex gap-2.5">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about active threats, CSPM findings, or draft Terraform / CLI remediations..."
            className="flex-1 px-4 py-2.5 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/40 text-foreground text-sm"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="bg-primary hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg font-medium text-sm transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            <Send className="w-4 h-4" />
            <span>Send</span>
          </button>
        </form>
      </div>
    </div>
  );
}
