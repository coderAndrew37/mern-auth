import React from "react";
import { assets } from "../assets/assets";

const NavBar = () => {
  return (
    <div className="flex justify-between items-center p-4 sm:p-8 sm:px-16 w-full absolute top-0 ">
      <img src={assets.logo} alt="Logo" className="w-28 sm:w-32" />

      <button className="px-4 py-2 text-gray-800 rounded-full border border-gray-500 flex items-center gap-2 hover:bg-gray-100 transition-all">
        Login <img src={assets.arrow_icon} alt="" />
      </button>
    </div>
  );
};

export default NavBar;
