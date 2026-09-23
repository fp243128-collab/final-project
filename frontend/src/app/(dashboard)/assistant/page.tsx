"use client";

import { useState, useRef, useEffect } from "react";
import { Bot, User, Send, Loader2 } from "lucide-react";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      role: "assistant",
      content: "Hello! I am SentinelX AI. How can I help you secure your infrastructure today?\n\n*(Try asking me about \"Public S3 Buckets\" or \"SSH Brute Force attacks\")*"
    }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg: Message = { id: Date.now().toString(), role: "user", content: input };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const response = await fetch("http://localhost:8000/api/assistant/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: userMsg.content }),
      });
      const data = await response.json();
      
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.response
      }]);
    } catch (error) {
      console.error(error);
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "Sorry, I encountered an error communicating with the server."
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  // Basic markdown parser for the demo
  const renderMessageContent = (content: string) => {
    // Split by code blocks
    const parts = content.split(/(```[\s\S]*?```)/g);
    
    return parts.map((part, index) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        // It's a code block
        const code = part.replace(/```(bash)?/g, '').trim();
        return (
          <div key={index} className="bg-gray-900 text-gray-100 p-4 rounded-md my-3 font-mono text-sm overflow-x-auto">
            <pre>{code}</pre>
          </div>
        );
      }
      
      // Handle bolding and newlines
      const formattedText = part
        .split('\n')
        .map((line, i) => {
          if (!line) return <br key={`br-${i}`} />;
          
          // Basic bolding
          const boldedLine = line.split(/(\*\*.*?\*\*)/g).map((segment, j) => {
            if (segment.startsWith('**') && segment.endsWith('**')) {
              return <strong key={`bold-${j}`} className="font-bold text-gray-900">{segment.slice(2, -2)}</strong>;
            }
            return <span key={`text-${j}`}>{segment}</span>;
          });

          return (
            <p key={`p-${i}`} className="mb-2">
              {boldedLine}
            </p>
          );
        });

      return <div key={index}>{formattedText}</div>;
    });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] max-w-4xl mx-auto bg-surface border border-sentinel rounded-xl shadow-sm overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-border bg-gray-50 flex items-center gap-3">
        <div className="w-10 h-10 bg-primary/10 rounded-full flex items-center justify-center">
          <Bot className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h1 className="font-semibold text-foreground">SentinelX AI</h1>
          <p className="text-xs text-muted flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-green-500"></span> Online
          </p>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {messages.map((msg) => (
          <div key={msg.id} className={`flex gap-4 ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
            <div className={`w-8 h-8 shrink-0 rounded-full flex items-center justify-center ${
              msg.role === 'user' ? 'bg-gray-200 text-gray-700' : 'bg-primary text-white'
            }`}>
              {msg.role === 'user' ? <User className="w-5 h-5" /> : <Bot className="w-5 h-5" />}
            </div>
            
            <div className={`max-w-[80%] rounded-2xl px-5 py-3 ${
              msg.role === 'user' 
                ? 'bg-blue-50 text-blue-900 rounded-tr-none border border-blue-100' 
                : 'bg-white border border-gray-200 text-gray-700 rounded-tl-none shadow-sm'
            }`}>
              {renderMessageContent(msg.content)}
            </div>
          </div>
        ))}
        
        {isLoading && (
          <div className="flex gap-4 flex-row">
            <div className="w-8 h-8 shrink-0 rounded-full flex items-center justify-center bg-primary text-white">
              <Bot className="w-5 h-5" />
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl rounded-tl-none px-5 py-4 shadow-sm flex items-center gap-2">
              <Loader2 className="w-4 h-4 text-muted animate-spin" />
              <span className="text-sm text-muted">Thinking...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 bg-white border-t border-border">
        <form onSubmit={handleSubmit} className="flex gap-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask SentinelX AI about alerts, remediations, or architecture..."
            className="flex-1 px-4 py-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 text-foreground text-sm"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="bg-primary hover:bg-blue-700 text-white px-5 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            <Send className="w-4 h-4" />
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
