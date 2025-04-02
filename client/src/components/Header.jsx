import React from "react";
import { assets } from "../assets/assets";

const Header = () => {
  return (
    <div className="flex flex-col items-center text-center mt-20 px-4 text-gray-800 ">
      <img
        className="w-36 h-36 rounded-full mb-6 "
        src={assets.header_img}
        alt=""
      />

      <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
        Hey Developer{" "}
        <img className="w-8 aspect-square" src={assets.hand_wave} alt="" />
      </h1>

      <h2 className="text-2xl font-semibold mb-4 sm:text-5xl">
        Welcome to our app
      </h2>
      <p className="max-w-md mb-8 sm:text-2xl">
        Lets get started with a quick product tour and we will have you up and
        running in no time
      </p>
      <button className="px-4 py-2 bg-gray-800 text-white rounded-full hover:bg-gray-700 transition-all">
        Get Started
      </button>
    </div>
  );
};

export default Header;
