import React, {useState, useContext} from 'react'
import { FaArrowLeft } from "react-icons/fa";
import { AuthDataContext } from '../context/AuthContext';
import Nidra from '../assets/Nidra.png'
const Login = () => {
 const [currState, setcurrState] = useState("Sign Up")
  const [fullName, setfullName] = useState("")
  const [email, setemail] = useState("")
  const [password, setpassword] = useState("")
  
  const {userData, setUserData, login} = useContext(AuthDataContext)

  const onSubmitHandler = (event) => {
    event.preventDefault();

    login(currState === "Sign Up" ? 'signup' : 'login', {fullname: fullName, email, password})

  }

  return (
    <div  style={{
    backgroundImage: `linear-gradient(to bottom, rgba(59,130,246,0.7), rgba(147,51,234,0.7)), url(${Nidra})`
  }} className={`min-h-screen bg-contain bg-center flex items-center justify-center gap-3 max-sm:flex-col backdrop-blur-3xl`}>

      {/* ---------------left--------------- */}

      {/* <img src={Nidra} alt="Nidra Logo" className='w-[min(30vw,300px)] rounded-lg' /> */}

      {/* -----------------right--------------- */}

      <form onSubmit={onSubmitHandler} className='border-2 bg-transparent text-white border-blue-500 p-6 flex flex-col gap-6 rounded-lg  shadow-blue-600 shadow-2xl '>
        <h1 className='flex text-3xl font-semibold items-center w-full justify-between'>
          {currState}
        </h1>

        {currState === "Sign Up" && (
          <input onChange={(e) => { setfullName(e.target.value) }} value={fullName} type="text" className='p-2 px-4 border border-gray-500 rounded-md focus:outline-none' placeholder='Full Name' required />
        )
        }
     
            
              <input onChange={(e) => { setemail(e.target.value) }} value={email} type="email" placeholder='Email Address' required className='p-2 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus: ring-indigo-500' />
              <input onChange={(e) => { setpassword(e.target.value) }} value={password} type="password" placeholder='Password' required className='p-2 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus: ring-indigo-500' />


        <button type='submit' className='py-3 bg-gradient-to-r from-purple-400
         to-violet-600 text-white rounded-md cursor-pointer'>
          {currState === 'Sign Up' ? "Create Account" : "Login Now"}
        </button>

        <div className='flex gap-2 text-md text-white-800'>
          <input type="checkbox" />
          <p>Agree to the term of use and privacy.</p>
        </div>

        <div className='flex flex-col gap-2'>
          {
            currState === 'Sign Up' ? (
              <p className='text-md text-white'>Already have an Account? <span onClick={() => { setcurrState("Login"); }} className='font-medium text-violet-900 cursor-pointer'>
                Login here
              </span></p>

            ) : (
              <p className='text-md text-white'>Create an Account? <span className='font-medium text-blue-900 cursor-pointer' onClick={() => { setcurrState("Sign Up"); }} >Click here</span> </p>
            )

          }

        </div>

      </form>

    </div>
  )
}

export default Login