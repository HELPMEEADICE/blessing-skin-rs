import React from 'react'
import { hot } from 'react-hot-loader/root'

type HomeData = {
  title: string
  login: string
  browse_skinlib: string
}

const Home: React.FC = () => {
  const { title, login, browse_skinlib } = blessing.extra.home as HomeData

  return (
    <>
      <h1>{blessing.site_name}</h1>
      <p>{title}</p>
      <a href="/auth/login">{login}</a> <a href="/skinlib">{browse_skinlib}</a>
    </>
  )
}

export default hot(Home)
