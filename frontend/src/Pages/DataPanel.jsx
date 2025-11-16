import React, {useContext, useEffect} from "react";
import { sidebarDataContext } from "../context/SidebarContext";
import { useNavigate } from "react-router-dom";

export default function DataPanel() {

  const {itmDataPannel, setItmDataPannel} = useContext(sidebarDataContext)
  const navigate = useNavigate();

  useEffect(() => {
     if(!itmDataPannel){
       navigate('/events');
      //  console.log("No item in data pannel")
     }
    //  console.log(itmDataPannel)
  }, [itmDataPannel])
  

  return (

       itmDataPannel && <div className="flex justify-center w-full items-center min-h-screen bg-gray-100 p-6">
     
          {/* Main content */}
          <div className="flex justify-center items-start gap-3 rounded-xl flex-col w-[650px] bg-gray-300 p-5 text-gray-800">
            <p className="text-2xl m-1"><strong className="m-4">Rule:</strong> {itmDataPannel.rule}</p>
            <p className="text-2xl m-1"><strong className="m-4">Path:</strong> {itmDataPannel.path}</p>
            <p className="text-2xl m-1"><strong className="m-4">Severity:</strong> {itmDataPannel.severity}</p>
            <p className="text-2xl m-1"><strong className="m-4">IP Address:</strong> {itmDataPannel.ip_address}</p>
            <p className="text-2xl m-1"><strong className="m-4">Description:</strong> {itmDataPannel.description}</p>
            <p className="text-2xl m-1"><strong className="m-4">User_Agent:</strong> {itmDataPannel.user_agent}</p>
            {/* <p className="text-2xl m-1"><strong className="m-4">Headers:</strong> {itmDataPannel.headers}</p> */}
            <p className="text-2xl m-1"><strong className="m-4">Time:</strong> {itmDataPannel.timestamp.split("T")[0]}</p>

            <div className="flex gap-10 ml-4 mt-8">
              <button className="bg-red-500 text-white cursor-pointer text-xl px-[67px] py-3 rounded-lg hover:bg-red-600 transition">
                Block
              </button>
              <button className="bg-gray-500 text-white cursor-pointer px-[67px] py-3 text-xl rounded-lg hover:bg-gray-600 transition">
                Delete
              </button>
            </div>
          </div>

        </div>
     
  );
}
