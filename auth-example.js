import NextAuth from "next-auth";
import bcrypt from "bcryptjs"
import CredentialProvider from "next-auth/providers/credentials";
import dbConnect from "../../../config/dbConnect";
import User from "../../../models/User"
import { NEXTAUTH_SECRECT } from "../../../config";




export default NextAuth({
  providers: [
    CredentialProvider({
      name: "Credentials",
      id: 'username-login',
      credentials: {
        username: {
          label: "Email",
          type: "text",
          placeholder: "johndoe@test.com",
        },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        // database look up
        await dbConnect();

        const adminUser = await User.findOne({ email: credentials.username })
        if (!adminUser) {
          // console.log("=========NO USER WITH EMAIL FOUND In DB ========")
          throw new Error("No User Found")
        }
        if (adminUser.accessType != 'system-agent-access') {
          // console.log("=========NO USER WITH EMAIL FOUND In DB ========")
          throw new Error("You Do Not Have Permission To Access This Portal")
        }


        // Match password
        const vPass = bcrypt.compareSync(credentials.password, adminUser.password);
        if (vPass) {
          return {
            id: adminUser._id,
            fname: adminUser.firstName,
            lname: adminUser.lastName,
            email: adminUser.email,
            jobTitle: adminUser.jobTitle,
            profilePicture: adminUser.profilePicture,
            sex: adminUser.sex,
            memberSince: adminUser.date,
            role: adminUser.role,
            timezone: adminUser.timezone,
            officeName: adminUser.officeName,
          }

        }

        // console.log("=========PASSWORD DOES NOT MATCH: RETRY ========")
        throw Error("Password Incorrect")



      },
    }),
  ],

  callbacks: {

    jwt: ({ token, user }) => {
      // first time jwt callback is run, user object is available
      if (user) {
        token.id = user.id;
        token.fname = user.fname;
        token.lname = user.lname;
        token.jobTitle = user.jobTitle;
        token.profilePicture = user.profilePicture;
        token.sex = user.sex;
        token.memberSince = user.memberSince;
        token.role = user.role;
        token.timezone = user.timezone;
        token.officeName = user.officeName;

        // console.log("FROM NEXT JWT AUTH===>",token, user)
      }
      return token;
    },

    session: ({ session, token, user }) => {
      
      if (token) {

        session.id = token.id;
        session.fname = token.fname;
        session.lname = token.lname;
        session.jobTitle = token.jobTitle;
        session.profilePicture = token.profilePicture;
        session.sex = token.sex;
        session.memberSince = token.memberSince;
        session.role = token.role;
        session.timezone = token.timezone;
        session.officeName = token.officeName;


        // console.log("FROM NEXT Session AUTH===>", session, token, user)
      }

      return session;
    },


  },


  secret: NEXTAUTH_SECRECT,

  session: {
    maxAge: 10 * 60, // 10 Minutes (Sign out user after 10 minutes of inactivity)
    strategy: 'jwt'
  },

  jwt: {
    secret: NEXTAUTH_SECRECT,
    encryption: true,
    maxAge: 10 * 60,  // 10 Minutes (Sign out user after 10 minutes of inactivity)
  },

  pages: {
    signIn: "/auth/signin",
    signOut: "/auth/signout",
    error: "/auth/signin",
    // verifyRequest: "http://localhost:3000/auth/signin",
  },

});