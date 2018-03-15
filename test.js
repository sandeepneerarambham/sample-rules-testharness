'use strict';

var fs = require('fs');
var expect = require('chai').expect;
var should = require('chai').should();
require('dotenv').config();
var runInSandbox = require("auth0-rules-testharness");

var context = {};

var configuration = {};

var params = {
  timeout: 5,
  ca: '',
  tenant: process.env.AUTH0_TENANT,
  url: process.env.SANDBOX_URL,
  token: process.env.WEBTASK_TOKEN
};



describe('auth0-rules-testharness', function () {

  var user;

  beforeEach(function () {
    user = {
      user_id: '00132926883',
      nickname: '00132926883',
      given_name: 'Puneet',
      family_name: 'Singhal',
      name: 'Puneet Singhal',
      email: 'TEST1231234143@TESTMAIL.COM',
      email_verified: true,
      user_metadata: {},
      app_metadata: {},
      cris_Member_LastLoginDate: '2017-02-02T12:19:30',
      cris_Member_ActiveCardNo: '00132926883',
      cris_Member_FirstName: 'Puneet',
      cris_Member_LastName: 'Singhal',
      cris_Member_EmailAddress: 'TEST1231234143@TESTMAIL.COM',
      cris_Member_MobileNumber: '55555555555',
      cris_Member_IsMobileVerified: 'Y',
      cris_Member_IsEmailVerified: 'Y',
      cris_Member_PersonID: '1538316',
      cris_Member_MemProgram: 'OM',
      cris_Member_Title: 'Mr',
      cris_Member_Gender: 'M',
      cris_Member_CountryOfResidence: 'IN',
      cris_Member_PointsBalanace: '2611',
      cris_Member_Tier: 'BLUE',
      cris_Member_FlagSiteRegistered: 'Y',
      cris_Member_ActiveStatus: 'ACT',
      cris_Member_MergedCardNo: ''
    };
  })

  it('should return user object successfully with cris_Member_FlagSiteRegistered equal to Y', function (done) {

    this.timeout(10000);
    var script = fs.readFileSync('./rules/passwordResetCheck.js', 'utf8');
    var callback = function (err, result, output, stats) {
      should.not.exist(err);
      console.log('result: ', result);
      expect(result.user_id).to.equal('00132926883');
      done();
    };
    // set flag to influence expected result
    user.cris_Member_FlagSiteRegistered = 'Y';
    var args = [user, context, callback];
    runInSandbox(script, args, configuration, params);
  });

    it('should return user object successfully with cris_Member_FlagSiteRegistered equal to R', function (done) {

    this.timeout(10000);
    var script = fs.readFileSync('./rules/passwordResetCheck.js', 'utf8');
    var callback = function (err, result, output, stats) {
      should.not.exist(err);
      console.log('result: ', result);
      expect(result.user_id).to.equal('00132926883');
      done();
    };
    // set flag to influence expected result
    user.cris_Member_FlagSiteRegistered = 'R';
    var args = [user, context, callback];
    runInSandbox(script, args, configuration, params);
  });

  it('should throw error with cris_Member_FlagSiteRegistered equal to N', function (done) {

    this.timeout(10000);
    var script = fs.readFileSync('./rules/passwordResetCheck.js', 'utf8');
    var callback = function (err, result, output, stats) {
      should.not.exist(result);
      should.exist(err);
      console.log(err);
      expect(err.message).to.equal('Password_Reset_Required');
      done();
    };
    // set flag to influence expected result
    user.cris_Member_FlagSiteRegistered = 'N';
    var args = [user, context, callback];
    runInSandbox(script, args, configuration, params);
  });

  it('should throw error with cris_Member_FlagSiteRegistered equal to null', function (done) {

    this.timeout(10000);
    var script = fs.readFileSync('./rules/passwordResetCheck.js', 'utf8');
    var callback = function (err, result, output, stats) {
      should.not.exist(result);
      should.exist(err);
      console.log(err);
      expect(err.message).to.equal('Password_Reset_Required');
      done();
    };
    // set flag to influence expected result
    user.cris_Member_FlagSiteRegistered = null; 
    var args = [user, context, callback];
    runInSandbox(script, args, configuration, params);
  });

  it('should throw error with cris_Member_FlagSiteRegistered is omitted altogether', function (done) {

    this.timeout(10000);
    var script = fs.readFileSync('./rules/passwordResetCheck.js', 'utf8');
    var callback = function (err, result, output, stats) {
      should.not.exist(result);
      should.exist(err);
      console.log(err);
      expect(err.message).to.equal('Password_Reset_Required');
      done();
    };
    // set flag to influence expected result
    delete user.cris_Member_FlagSiteRegistered;
    var args = [user, context, callback];
    runInSandbox(script, args, configuration, params);
  });

});