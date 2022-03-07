const Yup = require('yup');

exports.auth = Yup.object().shape({
  email: Yup.string().email().required(),
  password: Yup.string().required(),
});
