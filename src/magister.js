import HTTP from "./util/http";
import Session from "./session";

/** Main class for authenticating with Magister
 * @prop {Boolean} authenticated - Boolean set to true if currently authenticated
 * @prop {Session} session - The currently authenticated session
 */
class Magister {
  /**
   * Initialize a new Magister instance with credentials
   * @param {String} school - The url of the school (including https)
   * @param {String} username - The username of your Magister account
   * @param {String} password - The password of your Magister account
   */
  constructor(school, username, password) {
    this.school = school;
    this.username = username;
    this.password = password;

    this.authenticated = false;
    this.session;
  }

  /**
   * Authenticates with Magister
   * @param {String} [savedAuth] - The saved auth string for reuse of the session
   * @returns {Promise<Session>} A session object
   */
  authenticate(savedAuth) {
    return new Promise((resolve, reject) => {
      if (savedAuth) {
        const data = JSON.parse(savedAuth);
        if (data.schoolUrl && data.sessionId && data.bearerToken) {
          const session = new Session(data.sessionId, data.bearerToken, data.schoolUrl);
          this.session = session;
          this.session
            .initialize()
            .then(() => {
              resolve(session);
            })
            .catch(() => {
              reject(new Error("Session expired!"));
            });
        } else {
          reject(new Error("Auth object invalid!"));
        }
      } else {
        if (this.school && this.username && this.password) {
          if (this.school.length < 3) {
            reject(new Error("School name must be longer than 3 characters"));
          }

          this._login(this)
            .then(resolve)
            .catch(reject);

        } else {
          reject(new Error("Please set all parameters before authenticating!"));
        }
      }
    });
  }

  _login(self) {
    return new Promise((resolve, reject) => {
      const school = self.school;
      const schoolDomain = school.split("https://")[1];// The school url excluding the protocol
      const authorizeUrl = `https://accounts.magister.net/connect/authorize?client_id=M6-${schoolDomain}&redirect_uri=https%3A%2F%2F${schoolDomain}%2Foidc%2Fredirect_callback.html&response_type=id_token%20token&scope=openid%20profile%20magister.ecs.legacy%20magister.mdv.broker.read%20magister.dnn.roles.read&state=29302702b955469f84d342fcb4cece33&nonce=8cfe9935b3a14fc593f328663d14f191&acr_values=tenant%3A${schoolDomain}`;

      HTTP.get(authorizeUrl, {
        maxRedirects: 0,
        validateStatus: status => {
          return status === 302;
        }
      })
        .then(response => {
          const returnUrl = decodeURIComponent(
            response.headers.location.split("returnUrl=")[1]
          );

          HTTP.get(response.headers.location, {
            maxRedirects: 0,
            validateStatus: status => {
              return status === 302;
            }
          })
            .then(response => {
              const sessionId = response.headers.location
                .split("?")[1]
                .split("&")[0]
                .split("=")[1];
              const authUrl = "https://accounts.magister.net/challenge/";
              let xsrf = response.headers["set-cookie"][1]
                .split("XSRF-TOKEN=")[1]
                .split(";")[0];
              const authCookies = response.headers["set-cookie"].toString();

              HTTP.post(authUrl + "username", {
                data: {
                  sessionId: sessionId,
                  returnUrl: returnUrl,
                  username: self.username
                },
                headers: {
                  Cookie: authCookies,
                  "X-XSRF-TOKEN": xsrf
                }
              })
                .then(response => {
                  HTTP.post(authUrl + "password", {
                    data: {
                      sessionId: sessionId,
                      returnUrl: returnUrl,
                      password: self.password
                    },
                    headers: {
                      Cookie: authCookies,
                      "X-XSRF-TOKEN": xsrf
                    }
                  })
                    .then(response => {
                      HTTP.get("https://accounts.magister.net" + returnUrl, {
                        headers: {
                          Cookie: response.headers["set-cookie"],
                          "X-XSRF-TOKEN": xsrf
                        },
                        maxRedirects: 0,
                        validateStatus: status => {
                          return status === 302;
                        }
                      })
                        .then(response => {
                          self.authenticated = true;
                          const bearerToken = response.headers.location
                            .split("&access_token=")[1]
                            .split("&")[0];
                          const session = new Session(
                            sessionId,
                            bearerToken,
                            school
                          );
                          this.session = session;
                          session
                            .getProfileInfo()
                            .then(() => {
                              resolve(session);
                            })
                            .catch(reject);
                        })
                        .catch(reject);
                    })
                    .catch(err => {
                      reject(new Error("Password incorrect!"));
                    });
                })
                .catch(err => {
                  reject(new Error("Username incorrect!"));
                })
                .catch(reject);
            })
            .catch(reject);
        })
        .catch(reject);
    });
  }
};

/**
 * Searches for schools with specific name
 * @param {String} schoolName - The search query
 * @returns {Array} - Returns an array of matching schools
 */
function findSchool(schoolName) {
  return new Promise((resolve, reject) => {
    HTTP.get(`https://mijn.magister.net/api/schools?filter=${schoolName}`)
      .then(response => {
        if (!response.data.Message) {
          resolve(response.data);
        } else {
          reject(response.data.message);
        }
      })
      .catch(reject);
  });
}

/**
 * Collects list of all Magister schools
 * @returns {Array} - Returns an array of all Magister schools
 */
function getSchoolList() {
  return new Promise((resolve, reject) => {
    HTTP.get(`https://mijn.magister.net/api/schools?filter=%%%`)
      .then(response => {
        if (!response.data.Message) {
          resolve(response.data);
        } else {
          reject(response.data.message);
        }
      })
      .catch(reject);
  });
}

export default Magister;
export {findSchool, getSchoolList};