import React, { useState } from "react";
import { assets } from "../assets/assets";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const [state, setState] = useState("Sign Up");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const navigate = useNavigate();

  return (
    <div className="flex items-center justify-center h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400">
      <img
        onClick={() => navigate("/")}
        src={assets.logo}
        alt=""
        className="absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer"
      />

      <div className="bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm">
        <h2 className=" text-3xl font-bold text-white text-center mb-2">
          {state === "Sign Up" ? "Sign Up" : "Login"}
        </h2>

        <p className="text-center text-sm mb-6 ">
          {state === "Sign Up" ? "Create my account" : "Login to my account"}
        </p>

        <form>
          {state === "Sign Up" && (
            <div className="flex flex-items-center gap-3 w-full mb-4 px-5 py-2 bg-[#333A5C] rounded-full">
              <img src={assets.person_icon} alt="" />
              <input
                onChange={(e) => setName(e.target.value)}
                value={name}
                className="bg-transparent outline-none text-white "
                type="text"
                placeholder="Name"
                required
              />
            </div>
          )}

          <div className="flex flex-items-center gap-3 w-full mb-4 px-5 py-2 bg-[#333A5C] rounded-full">
            <img src={assets.mail_icon} alt="" />
            <input
              onChange={(e) => setEmail(e.target.value)}
              value={email}
              className="bg-transparent outline-none text-white "
              type="email"
              placeholder="Email"
              required
            />
          </div>
          <div className="flex flex-items-center gap-3 w-full mb-4 px-5 py-2 bg-[#333A5C] rounded-full">
            <img src={assets.lock_icon} alt="" />
            <input
              onChange={(e) => setPassword(e.target.value)}
              value={password}
              className="bg-transparent outline-none text-white "
              type="password"
              placeholder="Password"
              required
            />
          </div>

          <p
            onClick={() => navigate("/reset-password")}
            className="text-center text-sm mb-6 cursor-pointer text-indigo-500"
          >
            Forgot Password?
          </p>

          <button className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-indigo-900 text-white rounded-full hover:from-indigo-600 hover:to-indigo-900 w-full cursor-pointer transition-all">
            {state}
          </button>
        </form>

        <p className="text-center text-sm mt-6">
          {state === "Sign Up"
            ? "Already have an account? "
            : "Don't have an account? "}
          <span
            className="text-indigo-500 cursor-pointer"
            onClick={() => setState(state === "Sign Up" ? "Login" : "Sign Up")}
          >
            {state === "Sign Up" ? "Login" : "Sign Up"}
          </span>
        </p>
      </div>
    </div>
  );
};

export default Login;
