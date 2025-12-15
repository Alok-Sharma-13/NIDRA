import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import SidebarContext from './context/SidebarContext.jsx'
import { BrowserRouter } from 'react-router-dom'
import AuthContext from './context/AuthContext.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <AuthContext>
        <SidebarContext>
          <App />
        </SidebarContext>
      </AuthContext>
    </BrowserRouter>
  </StrictMode>,
)
