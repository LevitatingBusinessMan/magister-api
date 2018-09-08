const {
  default: Magister
} = require('../dist/magister')
const chai = require('chai')
const mConf = require('./magisterConfig.json')
const expect = chai.expect
let session

describe('Magister', function () {
  const magister = new Magister(mConf.schoolName, mConf.username, mConf.password)

  describe('#findSchool', function () {
    it('Should be able to find a school by name', function () {
      return magister.findSchool('baudartius')
        .then(schools => {
          expect(schools[0].Name).to.equal('Baudartius College')
        })
    })
  })

  describe('#authenticate', function () {
    it('Should be able to authenticate with Magister servers', function () {
      return magister.authenticate()
        .then(newSession => {
          session = newSession
        })
    })
  })
})

describe('Session', function () {
  describe('#getProfileInfo', function () {
    it("Should be able to retrieve profile info", function () {
      return session.getProfileInfo()
        .then(profile => {
          expect(typeof profile).to.equal('object')
        })
    })
  })

  describe('#getAppointments', function () {
    it("Should be able to retrieve appointments", function () {
      return session.getAppointments(new Date(), new Date())
        .then(appointments => {
          expect(typeof appointments).to.equal('object')
        })
    })
  })
})