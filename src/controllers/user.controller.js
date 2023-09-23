const catchError = require("../utils/catchError");
const User = require("../models/User");
const { verifyAccount } = require("../utils/verifyAccount");
const EmailCode = require("../models/EmailCode");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sendResetPassword } = require("../utils/sendResetPassword");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  //desectrucutacion del body
  const { email, firstName, frontBaseUrl } = req.body;
  // se crea el usuario
  const result = await User.create(req.body);

  // se crea un codigo
  const code = require("crypto").randomBytes(64).toString("hex");

  //  se crea la funcion a donde llega el correo en el verifyAccount.js
  verifyAccount(email, firstName, frontBaseUrl, code);

  // a un usuario se le agrega un codigo especifico
  await EmailCode.create({ code, userId: result.id });

  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.destroy({ where: { id } });
  if (!result) return res.sendStatus(404);
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  delete req.body.password;
  delete req.body.isVerified;
  delete req.body.email;

  const result = await User.update(req.body, {
    where: { id },
    returning: true,
  });
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyUser = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });

  if (!emailCode) return res.sendStatus(401);

  const user = await User.update(
    { isVerified: true },
    { where: { id: emailCode.userId }, returning: true }
  );

  if (user[0] === 0) return res.sendStatus(404);

  await emailCode.destroy();

  return res.json(user[1][0]);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) return res.sendStatus(401);

  if (!user.isVerified) return res.sendStatus(401);

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.sendStatus(401);

  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });

  return res.json({ user, token });
});

const logged = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});

const resetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;

  const user = await User.findOne({ where: { email } });

  if (!user) return res.sendStatus(401);

  // se crea un codigo
  const code = require("crypto").randomBytes(64).toString("hex");

  console.log(code);

  // se envia el correo se cambia la ruta del correo y se modifica
  sendResetPassword(email, user.firstName, frontBaseUrl, code);

  // se guarda el codigo y el id del usuario
  await EmailCode.create({ code, userId: user.id });

  return res.json(user);
});

const updatePassword = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.sendStatus(401);

  const hashPassword = await bcrypt.hash(req.body.password, 10);

  const user = await User.update(
    { password: hashPassword },
    { where: { id: emailCode.userId }, returning: true }
  );

  if (user[0] === 0) return res.sendStatus(404);

  return res.json(user[1][0]);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyUser,
  login,
  logged,
  resetPassword,
  updatePassword,
};
