import { useState, useContext } from 'react'
import Sidebar from './components/Sidebar'
import { ToastContainer, toast } from 'react-toastify';
import { sidebarDataContext } from './context/SidebarContext'

import ScrollableTable from './Pages/ScrollableTable'
import DataPanel from './Pages/DataPanel'
import { Navigate, Route, Routes } from 'react-router-dom'
import BlockedIp from './Pages/BlockedIp'
import High from './Pages/High'
import Rule from './Pages/Rule'
import Country from './Pages/Country'
import Events from './Pages/Events'
import { AuthDataContext } from './context/AuthContext'
import Login from './Pages/Login'
import SignUp from './Pages/SignUp'
 
function App() {

  const { sidebarVal, setsidebarVal, dataPanel, setdataPanel, reqHandler, blockedIPHandler, countryHandler, ruleHandler, highHandler, eventHandler } = useContext(sidebarDataContext)
  const {userData, setUserData, logout} = useContext(AuthDataContext)

  return (
   <>
      <div className="flex h-screen relative">

        {/*  --------------Sidebar---------------- */}
     { userData &&  <div className="w-[200px] bg-gray-100 pb-1 flex ">
          <div className='flex flex-col gap-3.5'>
            <div className="px-5 py-4 font-bold text-blue-700 border-b text-2xl border-gray-300">NIDRA</div>
            <Sidebar label="All Request" eventHandler= {reqHandler} />
            <Sidebar label="Events" eventHandler= {eventHandler} />
            <Sidebar label="country" eventHandler= {countryHandler} />
            <Sidebar label="Blocked IP" eventHandler= {blockedIPHandler} />
            <Sidebar label="Rule" eventHandler= {ruleHandler}/>
            <Sidebar label="High" eventHandler={highHandler } />
          </div>
         
        </div>}

        {/* Main Content */}
        <div className="flex-1 bg-white pl-1">

             {/* { dataPanel ? <ScrollableTable /> : <DataPanel /> } */}
             <Routes>
               <Route path='/signup' element = {<SignUp />} />
               <Route path='/login' element = {<Login />} />
              <Route path='/' element={userData ? <ScrollableTable /> : <Navigate to="/login" />} />
              <Route path='/events' element={userData ? <Events /> : <Navigate to="/login" /> } />
              <Route path='/datapanel' element={userData ? <DataPanel /> : <Navigate to="/login" />} />
              <Route path='/blockedip' element={userData ? <BlockedIp /> : <Navigate to="/login" />} />
              <Route path='/rule' element={userData ? <Rule /> : <Navigate to="/login" />} />
              <Route path='/high' element={userData ? <High /> : <Navigate to="/login" />} />
              <Route path='/countries' element={userData ? <Country /> : <Navigate to="/login" />} />
             </Routes>
        </div>
      { userData && <button onClick={logout} className='cursor-pointer absolute right-4 top-4 px-6 py-2.5 bg-red-500 mx-1 text-white font-semibold rounded-lg'>Logout</button>}
      </div>
      {/* </div> */}
      <ToastContainer position="top-right" autoClose={2000} hideProgressBar={true} newestOnTop={false} closeOnClick rtl={false} pauseOnFocusLoss draggable pauseOnHover theme="light"/>
    </> 
  )
}

export default App
