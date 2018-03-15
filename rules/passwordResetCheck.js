function passwordResetCheck(user, context, callback) {
  if (user.cris_Member_FlagSiteRegistered !== 'Y' && user.cris_Member_FlagSiteRegistered !== 'R') {
    // any other value should be treated as a Password Reset Request
    console.log('Password reset required:', user);
    // used by UI to identify password reset error
    var ERROR_CODE = 'Password_Reset_Required';
    return callback(new Error(ERROR_CODE));
  }
  // continue with authentication as normal
  return callback(null, user, context);
}