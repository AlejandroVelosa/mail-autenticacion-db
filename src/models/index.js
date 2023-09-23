const EmailCode = require("./EmailCode");
const User = require("./User");

//Emailcode => userId
User.hasOne(EmailCode); // userId
EmailCode.belongsTo(User);
