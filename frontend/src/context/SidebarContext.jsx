import React, { Children, createContext, useState } from 'react'
import { useNavigate } from 'react-router-dom';
export let sidebarDataContext = createContext();

const SidebarContext = ({children}) => {

   const [sidebarVal, setsidebarVal] = useState("Request");
   const [dataPanel, setdataPanel] = useState(false)
   const navigate = useNavigate()

   const reqHandler = () => { 
        navigate('/')
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

    const handleDataPanel = () => {
       navigate('/datapanel')
    }

   let value = {
  sidebarVal, setsidebarVal, dataPanel, setdataPanel, reqHandler, blockedIPHandler, countryHandler, ruleHandler, highHandler, handleDataPanel
}
  return (
    <sidebarDataContext.Provider value={value}>
        {children}
    </sidebarDataContext.Provider>
  )
}

export default SidebarContext