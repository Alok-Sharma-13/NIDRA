import React, { Children, createContext, useState } from 'react'
import { useNavigate } from 'react-router-dom';
export let sidebarDataContext = createContext();

const SidebarContext = ({children}) => {

   const [sidebarVal, setsidebarVal] = useState("All Request");
   const [itmDataPannel, setItmDataPannel] = useState(null)
   const [dataPanel, setdataPanel] = useState(false)
   const navigate = useNavigate()

   const alltraficData = [
             {"timestamp": "2025-11-03T15:53:26.310341", "ip_address": "127.0.0.1", "country": "Unknown", "method": "POST", "path": "/api/login", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "42", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:28.377807", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/logout", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "0"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:30.438414", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "GET", "path": "/home", "headers": {"Host": "localhost:5000", "User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive"}, "user_agent": "Mozilla/5.0"},
{"timestamp": "2025-11-03T15:53:32.503586", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "137", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:34.702078", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "156", "Content-Type": "applicaton/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:36.807480", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "116", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:38.928313", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "GET", "path": "/api/log/admin", "headers": {"Host": "localhost:5000", "User-Agent": "attacker", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive"}, "user_agent": "attacker"},
{"timestamp": "2025-11-03T15:53:41.100269", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/ip/block", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "20", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:53:43.165832", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/ip/unblock", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "20", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:24.905465", "ip_address": "127.0.0.1", "country": "Unknown", "method": "POST", "path": "/api/login", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "42", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:27.780844", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/logout", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "0"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:30.163654", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "GET", "path": "/home", "headers": {"Host": "localhost:5000", "User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive"}, "user_agent": "Mozilla/5.0"},
{"timestamp": "2025-11-03T15:54:32.509682", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "137", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:38.764480", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "156", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:40.826857", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/rules/analyze", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "116", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:42.966461", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "GET", "path": "/api/log/admin", "headers": {"Host": "localhost:5000", "User-Agent": "attacker", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive"}, "user_agent": "attacker"},
{"timestamp": "2025-11-03T15:54:45.142175", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/ip/block", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "20", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"},
{"timestamp": "2025-11-03T15:54:47.206391", "ip_address": "127.0.0.1", "country": "Invalid IP", "method": "POST", "path": "/api/ip/unblock", "headers": {"Host": "localhost:5000", "User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "keep-alive", "Content-Length": "20", "Content-Type": "application/json"}, "user_agent": "python-requests/2.32.3"}

   ]

 const eventData = [
  {
    "rule": "XSS Attempt",
    "description": "Signature match for pattern: <script.*?>",
    "severity": "high",
    "timestamp": "2025-11-03T15:53:32.523966",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "Low",
    "timestamp": "2025-11-03T15:53:32.523966",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "SQL Injection",
    "description": "Signature match for pattern: (union select|drop table|--)",
    "severity": "high",
    "timestamp": "2025-11-03T15:53:34.722990",
    "ip_address": "127.0.0.2",
    "path": "/products?id=1 union",
    "user_agent": "Mozilla/5.0",
    "headers": {
      "X-Test": "SQLi-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:53:36.828819",
    "ip_address": "127.0.0.3",
    "path": "/about",
    "user_agent": "sqlmap/1.5",
    "headers": {
      "X-Test": "UserAgent-Test"
    }
  },
  {
    "source": "honeypot",
    "ip_address": "127.0.0.1",
    "path": "/api/log/admin",
    "method": "GET",
    "timestamp": "2025-11-03T21:23:38",
    "rule": "Honeypot Path Accessed: ",
    "severity": "High"
  },
  {
    "rule": "XSS Attempt",
    "description": "Signature match for pattern: <script.*?>",
    "severity": "high",
    "timestamp": "2025-11-03T15:54:33.297850",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:54:33.297850",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:54:40.855720",
    "ip_address": "127.0.0.3",
    "path": "/about",
    "user_agent": "sqlmap/1.5",
    "headers": {
      "X-Test": "UserAgent-Test"
    }
  },
  {
    "source": "honeypot",
    "ip_address": "127.0.0.1",
    "path": "/api/log/admin",
    "method": "GET",
    "timestamp": "2025-11-03T21:24:43",
    "rule": "Honeypot Path Accessed:",
    "severity": "High"
  },
  {
    "rule": "XSS Attempt",
    "description": "Signature match for pattern: <script.*?>",
    "severity": "high",
    "timestamp": "2025-11-03T15:53:32.523966",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:53:32.523966",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "SQL Injection",
    "description": "Signature match for pattern: (union select|drop table|--)",
    "severity": "high",
    "timestamp": "2025-11-03T15:53:34.722990",
    "ip_address": "127.0.0.2",
    "path": "/products?id=1",
    "user_agent": "Mozilla/5.0",
    "headers": {
      "X-Test": "SQLi-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:53:36.828819",
    "ip_address": "127.0.0.3",
    "path": "/about",
    "user_agent": "sqlmap/1.5",
    "headers": {
      "X-Test": "UserAgent-Test"
    }
  },
  {
    "source": "honeypot",
    "ip_address": "127.0.0.1",
    "path": "/api/log/admin",
    "method": "GET",
    "timestamp": "2025-11-03T21:23:38",
    "rule": "Honeypot Path Accessed: ",
    "severity": "High"
  },
  {
    "rule": "XSS Attempt",
    "description": "Signature match for pattern: <script.*?>",
    "severity": "high",
    "timestamp": "2025-11-03T15:54:33.297850",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:54:33.297850",
    "ip_address": "127.0.0.1",
    "path": "/search?q=<script>alert(1)</script>",
    "user_agent": "curl/8.1",
    "headers": {
      "X-Test": "XSS-Test"
    }
  },
  {
    "rule": "Suspicious User-Agent",
    "description": "Signature match for pattern: sqlmap|nmap|curl",
    "severity": "medium",
    "timestamp": "2025-11-03T15:54:40.855720",
    "ip_address": "127.0.0.3",
    "path": "/about",
    "user_agent": "sqlmap/1.5",
    "headers": {
      "X-Test": "UserAgent-Test"
    }
  },
  {
    "source": "honeypot",
    "ip_address": "127.0.0.1",
    "path": "/api/log/admin",
    "method": "GET",
    "timestamp": "2025-11-03T21:24:43",
    "rule": "Honeypot Path Accessed:",
    "severity": "High"
  }
]
    
   const reqHandler = () => { 
        navigate('/')

    }

     const eventHandler = () => { 
        navigate('/events')

    }

    const blockedIPHandler = () => { 
        navigate('/blockedip')
    }
  
    const countryHandler = () => { 
        navigate('/countries')
    }

    const ruleHandler = () => { 
        navigate('/rule')
    }

    const highHandler = () => { 
        navigate('/high')
    }

    const handleDataPanel = (item) => {
      setItmDataPannel(item)
       navigate('/datapanel')
    }

   let value = {
  sidebarVal, setsidebarVal, dataPanel, setdataPanel, reqHandler, blockedIPHandler, countryHandler, ruleHandler, highHandler, handleDataPanel, eventHandler, alltraficData, eventData, itmDataPannel, setItmDataPannel
}
  return (
    <sidebarDataContext.Provider value={value}>
        {children}
    </sidebarDataContext.Provider>
  )
}

export default SidebarContext