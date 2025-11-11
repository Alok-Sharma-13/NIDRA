import React from "react";

export default function DataPanel() {
  const info = {
    country: "France",
    path: "/p1",
    severity: "Normal",
    request: "Normal",
    time: "5:00",
  };

  return (
    <div className="flex justify-center w-full items-center min-h-screen bg-gray-100 p-6">
     

          {/* Main content */}
          <div className="flex justify-center items-start gap-3 rounded-xl flex-col w-[650px] h-[500px] bg-gray-300 p-5  text-gray-800">
            <p className="text-3xl m-1"><strong className="m-4">Country:</strong> {info.country}</p>
            <p className="text-3xl m-1"><strong className="m-4">Path:</strong> {info.path}</p>
            <p className="text-3xl m-1"><strong className="m-4">Severity:</strong> {info.severity}</p>
            <p className="text-3xl m-1"><strong className="m-4">Request:</strong> {info.request}</p>
            <p className="text-3xl m-1"><strong className="m-4">Time:</strong> {info.time}</p>

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
