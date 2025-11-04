import { useState, useContext } from 'react'
import Sidebar from './components/Sidebar'
import HoneyPot from './components/HoneyPot'
import { sidebarContext } from './context/SidebarContext'
import Alerts from './components/Alerts'
import IPs from './components/IPs'
import Roles from './components/Roles'

function App() {

 const {sidebarVal, setsidebarVal} = useContext(sidebarContext)

  return (
    <>
      <div className="flex h-screen">
        {/* Sidebar */}
        <div className="w-48 bg-gray-100 flex flex-col justify-between">
          <div className='flex flex-col gap-3.5'>
            <div className="px-5 py-4 font-bold text-blue-700 border-b text-2xl border-gray-300">NIDRA</div>
            <Sidebar label="HoneyPot" />
            <Sidebar label="IP" />
            <Sidebar label="Role" />
            <Sidebar label="DB" />
            <Sidebar label="Alerts" />
            <Sidebar label="blocked IPs" />
          </div>
          <div>
            <Sidebar label="Settings" />
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 bg-white p-4">
          {/* <h1 className="text-xl font-semibold text-gray-700">Welcome to NIDRA Dashboard</h1> */}
        {  sidebarVal == "HoneyPot" && <HoneyPot />}
        {  sidebarVal == "IP" && <IPs />}
        {  sidebarVal == "Alerts" && <Alerts />}
        {  sidebarVal == "Role" && <Roles />}
        </div>
      </div>

    </>
  )
}

export default App
