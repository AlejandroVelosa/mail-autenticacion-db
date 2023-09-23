const { DataTypes } = require("sequelize");
const sequelize = require("../utils/connection");
const bcrypt = require("bcrypt");

const User = sequelize.define("user", {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  country: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  image: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  },
});

// sirve para  eliminar el password
User.prototype.toJSON = function () {
  const values = { ...this.get() };
  delete values.password;
  return values;
};
// sive para incriptar la contraseña
User.beforeCreate(async (user) => {
  const hashPassword = await bcrypt.hash(user.password, 10);
  user.password = hashPassword;
});

module.exports = User;
