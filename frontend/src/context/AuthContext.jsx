import React, { createContext, useState } from 'react'
import { useNavigate } from 'react-router-dom';

export const AuthDataContext = createContext();

const AuthContext = ({children}) => {

    const [userData, setUserData] = useState(null)
    const navigate = useNavigate()
      const login = async (state, credentials) => {
        try {
            // const {data} = await axios.post(`/api/auth/${state}`, credentials);
            // console.log(data)
            setUserData(credentials)
            navigate("/")
            alert("logged in successfully")
        } catch (error) {
            // console.log(error.message)
            // toast.error(error.message)
        }
    }

    const logout = () => {
          setUserData(null)
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