import React from "react";
import { Navigate } from "react-router-dom";
import { useMyContext } from "../store/ContextApi";

const ReverseAuthRoute = ({ children }) => {
  // Access the token and currentUser state by using the useMyContext hook from the ContextProvider
  const { currentUser } = useMyContext();

  // If the user is already logged in, redirect them away from login/signup to dashboard or home
  if (currentUser) {
    console.log("User already logged in");
    return <Navigate to="/notes" />;
  }

  // If there's no user, allow them to access the login/signup page
  return children;
};

export default ReverseAuthRoute;
