const catchError = require("../utils/catchError");
const User = require("../models/User");
const EmailCode = require("../models/EmailCode");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll({ include: [EmailCode] });
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const result = await User.create({
    email,
    password: hashedPassword,
    firstName,
    lastName,
    country,
    image,
  });

  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;

  await EmailCode.create({
    code,
    userId: result.id,
  });
  await sendEmail({
    to: email,
    subject: "Verificate your email",
    html: `
    
              <div>
                      <h1>Welcome ${firstName} ${lastName}</h1>

                      <p>Verify your account by checking this link:</p>
                      <a href="${link}">${link}</a>
                      
                      <br><hr>

                      <b>Thanks for signing up!</b>
              </div>
      `,
  });

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
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, country, image } = req.body;
  const result = await User.update(
    { firstName, lastName, country, image },
    {
      where: { id },
      returning: true,
    }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  if (!user.isVerified)
    return res.status(401).json({ error: "Email not verified" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ user }, process.env.TOKEN_SECRET);

  return res.status(201).json({ user, token });
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode)
    return res.status(401).json({
      message: "Invalid Code",
    });

  const user = await User.findByPk(emailCode.userId);
  user.isVerified = true;
  await user.save();
  await emailCode.destroy();

  return res.json(user);
});

const getLoggedUser = catchError(async (req, res) => {
  return res.json(req.user);
});

const postResetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/reset_password/${code}`;

  await EmailCode.create({
    code,
    userId: user.id,
  });
  await sendEmail({
    to: email,
    subject: "Reset your password",
    html: `
    
              <div>
                      <h1>Change your password by clicking this link:</h1>

                      
                      <a href="${link}">${link}</a>
                      
                      <br><hr>

                      <b>If you don't send this request please contact us!</b>
              </div>
      `,
  });

  return res.status(201).json(user);
});

const newPassword = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode)
    return res.status(401).json({
      message: "Invalid Code",
    });

  const { password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.findByPk(emailCode.userId);
  user.password = hashedPassword;
  await user.save();
  await emailCode.destroy();

  return res.status(201).json(user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  login,
  verifyCode,
  getLoggedUser,
  postResetPassword,
  newPassword,
};
