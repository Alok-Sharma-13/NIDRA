import React, { createContext, useState } from 'react'
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
export const AuthDataContext = createContext();

const AuthContext = ({children}) => {

    const [userData, setUserData] = useState(null)
    const navigate = useNavigate()
      const login = async (state, credentials) => {
        try {
            // const {data} = await axios.post(`/api/auth/${state}`, credentials);
            // console.log(data)
            setUserData(credentials)
            toast("logged in successfully")
            navigate("/")
        } catch (error) {
            // console.log(error.message)
            toast.error(error.message)
        }
    }

    const logout = () => {
          setUserData(null)
          toast("log Out Successfully")
          navigate("/login")

    }


    const value = {
        userData, setUserData, login, logout
    }

  return (
    <AuthDataContext.Provider value={value}>
        {children}
    </AuthDataContext.Provider>
  )
}

export default AuthContext