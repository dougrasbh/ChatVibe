import React from "react";
import { getAuth } from "firebase/auth";
import { useState, useEffect, useContext, useRef } from "react";
import { MessageContext } from "./App";
import { getDatabase, ref, get, onValue, off } from "firebase/database";
import { Link, useParams } from "react-router-dom";
export default function ContactBar() {
  const { userInfo, messages, names, userState,isSignedIn,filteredArr,setFilteredArr,originalRef } = useContext(MessageContext);
  const [lastMsg, setLastMsg] = useState("");
  const tempArr = [];



  return (
    <div
      className={
        "flex-1 border-r border-l border-borderColor w-72 flex-col md:flex-none md:flex" +
        (Object.keys(messages).length !== 0 ? " hidden" : " flex")
      }
    >
      <div className="mx-5">
        <input
          placeholder="Search"
          className=" z-50 w-full my-5 bg-inputColor rounded py-2 text-white pl-2 outline-none placeholder-borderColor shadow-sm shadow-slate-500"
          onChange={(event) => {
            console.log(event.target.value);
            if (event.target.value !== "") {
              const filteredResult = originalRef.current.filter(
                (value, index) => {
                  console.log(value.chatName);
                  return value.chatName.includes(event.target.value);
                }
              );
              console.log(
                "🚀 ~ file: ContactBar.js:46 ~ ContactBar ~ console.log(filteredArr):",
                filteredArr
              );
              setFilteredArr([...filteredResult]);
            } else {
              setFilteredArr([...originalRef.current]);
            }
          }}
        ></input>
      </div>
      {true ? (
        <div className="flex flex-col overflow-y-scroll">
          {filteredArr.map((value, index) => {
            const userKeys = value.participants?Object.keys(value.participants):{}
            const userValues = value.participants?Object.values(value.participants):{}
            return (
              <ContactBox
                name={value.type == "duo"
                ? userValues[1] && userValues[0]
                  ? userKeys[0] == isSignedIn.uid?userValues[1]:userValues[0]
                  : ""
                : value.chatName}
                key={index}
                lastMsg={value.lastMsg ? value.lastMsg : " "}
                pfp={value.type == "duo"
?userValues[1]&&userValues[0]
                  ? userKeys[0] == isSignedIn.uid?userValues[1][0].toUpperCase():userValues[0][0].toUpperCase()
                  : ""
                : value.pfp}
                chatKey={value.chatId}
                type={value.type}
              />
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

const ContactBox = ({ name, pfp, lastMsg, chatKey, type }) => {
  const { chatId } = useParams();
  const getColorFromLetter = (letter) => {
    const colors = [
      " bg-gradient-to-r from-red-500 to-pink-500",
      " bg-gradient-to-r from-yellow-500 to-green-500",
      " bg-gradient-to-r from-green-500 to-blue-500",
      " bg-gradient-to-r from-blue-500 to-indigo-500",
      " bg-gradient-to-r from-indigo-500 to-purple-500",
      " bg-gradient-to-r from-purple-500 to-pink-500",
      " bg-gradient-to-r from-pink-500 to-red-500",
      " bg-gradient-to-r from-gray-500 to-gray-700",
    ];

    // Get the index based on the letter's char code
    const index = letter.charCodeAt(0) % colors.length;
    return colors[index];
  };
  console.log(chatId, chatId);
  return (
    <Link to={`/homescreen/${chatKey}`}>
      <div
        className={
          "flex gap-2 h-16 items-center pl-5 border-t border-borderColor cursor-pointer hover:bg-slate-700" +
          (chatId == chatKey ? " bg-slate-800" : "")
        }
      >
        <button
          className={
            "flex w-10 h-10 justify-center items-center rounded-xl bg-stone-800 text-2xl" +
            (type == "duo" ? " text-base" + getColorFromLetter(name) : "")
          }
          onClick={() => {}}
        >
          {<p className={"text-white"}>{pfp}</p>}
        </button>
        <div>
          <p className="text-white">{name}</p>
          <p className=" text-subColor text-xs">
            {lastMsg.length >= 27 ? lastMsg.slice(0, 27) + "..." : lastMsg}
          </p>
        </div>
      </div>
    </Link>
  );
};
