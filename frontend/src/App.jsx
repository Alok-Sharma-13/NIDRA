import { useState, useContext } from 'react'
import Sidebar from './components/Sidebar'

import { sidebarDataContext } from './context/SidebarContext'

import ScrollableTable from './Pages/ScrollableTable'
import DataPanel from './Pages/DataPanel'
import { Route, Routes } from 'react-router-dom'
import BlockedIp from './Pages/BlockedIp'
import High from './Pages/High'
import Rule from './Pages/Rule'
import Country from './Pages/Country'

function App() {

  const { sidebarVal, setsidebarVal, dataPanel, setdataPanel, reqHandler, blockedIPHandler, countryHandler, ruleHandler, highHandler } = useContext(sidebarDataContext)

  return (
    <>
      <div className="flex h-screen">
        {/*  --------------Sidebar---------------- */}
        <div className="w-[200px] bg-gray-100 pb-1 flex flex-col justify-between">
          <div className='flex flex-col gap-3.5'>
            <div className="px-5 py-4 font-bold text-blue-700 border-b text-2xl border-gray-300">NIDRA</div>
            <Sidebar label="Request" eventHandler= {reqHandler} />
            <Sidebar label="Country" eventHandler= {countryHandler} />
            <Sidebar label="Blocked IP" eventHandler= {blockedIPHandler} />
            <Sidebar label="Rule" eventHandler= {ruleHandler}/>
            <Sidebar label="High" eventHandler={highHandler } />
          </div>
          <div>
            <Sidebar label="Settings" />
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 bg-white pl-1">

             {/* { dataPanel ? <ScrollableTable /> : <DataPanel /> } */}
             <Routes>
              <Route path='/' element={<ScrollableTable />} />
              <Route path='/datapanel' element={<DataPanel />} />
              <Route path='/blockedip' element={<BlockedIp />} />
              <Route path='/rule' element={<Rule />} />
              <Route path='/high' element={<High />} />
              <Route path='/countries' element={<Country />} />
             </Routes>

        </div>

      </div>

    </>
  )
}

export default App
