import React, { createContext, useContext, useState } from "react";
import { useEffect } from "react";
import api from "../services/api";
import toast from "react-hot-toast";

const ContextApi = createContext();

export const ContextProvider = ({ children }) => {
  //store the current loggedin user
  const [appLoading, setAppLoading] = useState(false);
  //store the current loggedin user
  const [currentUser, setCurrentUser] = useState(null);
  //handle sidebar opening and closing in the admin panel
  const [openSidebar, setOpenSidebar] = useState(true);
  //check the loggedin user is admin or not
  const [isAdmin, setIsAdmin] = useState(false);

  const fetchUser = async () => {
    if (!currentUser) {
      setAppLoading(true);
      try {
        const { data } = await api.get(`/auth/user`);
        const roles = data.data.roles;

        if (roles.includes("ROLE_ADMIN")) {
          setIsAdmin(true);
        } else {
          setIsAdmin(false);
        }
        setCurrentUser(data);
      } catch (error) {
        console.error("Error fetching current user", error);
      } finally {
        setAppLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  //through context provider you are sending all the datas so that we access at anywhere in your application
  return (
    <ContextApi.Provider
      value={{
        currentUser,
        setCurrentUser,
        openSidebar,
        setOpenSidebar,
        appLoading,
        isAdmin,
        setIsAdmin,
      }}
    >
      {children}
    </ContextApi.Provider>
  );
};

//by using this (useMyContext) custom hook we can reach our context provier and access the datas across our components
export const useMyContext = () => {
  const context = useContext(ContextApi);

  return context;
};
