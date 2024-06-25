export default class GithubUserDTO {
  constructor (userdata) {
    const profileemail = userdata.emails.slice(0, 1)
    const gitemail = profileemail[0]?.value

    this.first_name = userdata._json.name
    this.last_name = 'GitHub'
    this.age = 18
    this.email = gitemail
    this.password = 'GithubPassword'
  }
}
