import React from 'react'
type ReaptchaProps = {
  sitekey: string
  size?: 'normal' | 'invisible'
  onVerify(value: string): void
}

class Reaptcha extends React.Component<ReaptchaProps, {}> {
  execute() {
    this.props.onVerify('token')
  }

  reset() {}

  render() {
    return <></>
  }
}

export default Reaptcha
