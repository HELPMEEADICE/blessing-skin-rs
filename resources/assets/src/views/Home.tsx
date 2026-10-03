import React from 'react'
import { hot } from 'react-hot-loader/root'
import { t } from '@/scripts/i18n'

type HomeData = {
  title: string
  login: string
  register: string
  browse_skinlib: string
  user_center: string
  admin_panel: string
  logout: string
  description: string
  background: string
  fixed_bg: boolean
  hide_intro: boolean
  navbar_color: string
  authenticated: boolean
  user_id?: number
  user_label?: string
  permission?: number
  copyright_prefer: number
  copyright_text: string
}

const Home: React.FC = () => {
  const {
    login,
    register,
    browse_skinlib,
    user_center,
    admin_panel,
    logout,
    description,
    background,
    fixed_bg,
    hide_intro,
    navbar_color,
    authenticated,
    user_id,
    user_label,
    permission,
    copyright_prefer,
    copyright_text,
  } = blessing.extra.home as HomeData
  const copyrightTemplates = [
    'Powered with ❤ by Blessing Skin Server.',
    'Powered by Blessing Skin Server.',
    'Proudly powered by Blessing Skin Server.',
    '由 Blessing Skin Server 强力驱动。',
    '采用 Blessing Skin Server 搭建。',
    '使用 Blessing Skin Server 稳定运行。',
    '自豪地采用 Blessing Skin Server。',
  ]
  const copyright =
    copyrightTemplates[copyright_prefer] ?? copyrightTemplates[0]

  return (
    <>
      <div className="hp-wrapper">
        <img
          className={'home-background' + (fixed_bg ? ' fixed' : '')}
          src={background}
          alt=""
          aria-hidden="true"
        />
        <nav
          className={
            'navbar navbar-expand fixed-top navbar-' +
            navbar_color +
            ' navbar-light ml-0' +
            (blessing.extra.transparent_navbar ? ' transparent' : '')
          }
        >
          <div className="container">
            <a href="/" className="navbar-brand">
              {blessing.site_name}
            </a>
            <ul className="nav navbar-nav ml-auto">
              <li className="nav-item">
                <a className="nav-link" href="/skinlib">
                  {browse_skinlib}
                </a>
              </li>
              {authenticated ? (
                <li className="nav-item dropdown user-menu">
                  <a
                    href="/user"
                    className="nav-link d-flex align-items-center"
                  >
                    {user_id && (
                      <img
                        src={'/avatar/user/' + user_id + '?size=32'}
                        className="bs-avatar mr-2"
                        alt=""
                      />
                    )}
                    <span>{user_label}</span>
                  </a>
                  <div className="dropdown-menu dropdown-menu-lg dropdown-menu-right">
                    <a className="dropdown-item" href="/user">
                      {user_center}
                    </a>
                    {permission && permission > 0 && (
                      <a className="dropdown-item" href="/admin">
                        {admin_panel}
                      </a>
                    )}
                    <div className="dropdown-divider" />
                    <button
                      className="dropdown-item"
                      type="button"
                      id="logout-button"
                    >
                      {logout}
                    </button>
                  </div>
                </li>
              ) : (
                <li className="nav-item">
                  <a className="nav-link" href="/auth/login">
                    <i className="icon fas fa-sign-in-alt" aria-hidden="true" />{' '}
                    {login}
                  </a>
                </li>
              )}
            </ul>
          </div>
        </nav>

        <div className="container">
          <div className="splash">
            <h1 className="splash-head">{blessing.site_name}</h1>
            <p className="splash-subhead">{description}</p>
            <p>
              <a
                href={authenticated ? '/user' : '/auth/register'}
                className="main-button"
              >
                {authenticated ? user_center : register}
              </a>
            </p>
          </div>
        </div>

        {hide_intro ? (
          <div id="copyright" className="without-intro">
            <div className="container">
              {copyright} {copyright_text}
            </div>
          </div>
        ) : null}
      </div>

      {!hide_intro && (
        <>
          <section id="intro">
            <div className="container">
              <div className="text-center">
                <h1>{t('index.features.title')}</h1>
                <br />
                <br />
                <div className="container-lg">
                  <div className="row">
                    {(['first', 'second', 'third'] as const).map((feature) => (
                      <div className="col-lg" key={feature}>
                        <i
                          className={
                            'fas ' +
                            t('index.features.' + feature + '.icon') +
                            ' mb-3'
                          }
                          aria-hidden="true"
                        />
                        <h3>{t('index.features.' + feature + '.name')}</h3>
                        <p>{t('index.features.' + feature + '.desc')}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <br />
            </div>
          </section>
          <section id="footer-wrap">
            <div className="container">
              <div className="row">
                <div className="col-lg-6 mb-2">
                  {t('index.introduction', { sitename: blessing.site_name })}
                </div>
                <div className="col-lg-4" />
                <div className="col-lg-2 d-flex justify-content-center align-items-center">
                  <a href="/auth/register" className="main-button">
                    {t('index.start')}
                  </a>
                </div>
              </div>
            </div>
          </section>
          <div id="copyright" className="with-intro">
            <div className="container">
              {copyright} {copyright_text}
            </div>
          </div>
        </>
      )}
    </>
  )
}

export default hot(Home)
