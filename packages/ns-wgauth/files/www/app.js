/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-2.0-only
 */

'use strict'

const REFRESH_MS = 30000
const sections = ['loading', 'unavailable', 'refused', 'login', 'session']
const REFUSED = {
  blocked:
    'This VPN configuration is blocked: it seems to be used on more than one device at the same time. Contact your administrator.',
  no_user: 'This VPN configuration is not linked to a user yet. Contact your administrator.',
  no_otp: 'The one-time codes of your user are not set up. Contact your administrator for a new QR code.',
  device_required:
    'This VPN accepts logins only from the VPN app given by your administrator, on your enrolled device: a web browser can’t log in.'
}
const element = (id) => document.getElementById(id)
let refreshTimer

function show(id) {
  for (const section of sections) {
    element(section).hidden = section !== id
  }
}

async function api(method, path, body) {
  const options = { method, headers: {}, cache: 'no-store' }
  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(body)
  }
  const response = await fetch(path, options)
  let data = {}
  try {
    data = await response.json()
  } catch {
    // nginx error pages are not JSON
  }
  return { status: response.status, data }
}

function describeExpiry(iso) {
  const expires = new Date(iso)
  const minutes = Math.max(Math.round((expires - Date.now()) / 60000), 0)
  const hours = Math.floor(minutes / 60)
  const left = hours > 0 ? `${hours} h ${minutes % 60} min` : `${minutes} min`
  return `at ${expires.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} (in ${left})`
}

function showRefused(reason) {
  element('refused-message').textContent = REFUSED[reason]
  show('refused')
}

function showError(message) {
  const error = element('login-error')
  error.textContent = message
  error.hidden = !message
}

async function refresh() {
  clearTimeout(refreshTimer)
  let result
  try {
    result = await api('GET', '/api/status')
  } catch {
    result = { status: 0, data: {} }
  }
  if (result.status !== 200) {
    element('server').textContent = ''
    show('unavailable')
    return
  }
  const status = result.data
  element('server').textContent = status.server || ''
  if (status.authenticated) {
    element('user').textContent = status.user
    element('expires').textContent = describeExpiry(status.expires)
    show('session')
  } else if (status.blocked || status.no_user || status.no_otp) {
    showRefused(status.blocked ? 'blocked' : status.no_user ? 'no_user' : 'no_otp')
  } else if (status.device && status.device.required) {
    showRefused('device_required')
  } else {
    element('otp-field').hidden = !status.otp_required
    element('otp').required = Boolean(status.otp_required)
    if (element('login').hidden) {
      show('login')
      element('username').focus()
    }
  }
  refreshTimer = setTimeout(refresh, REFRESH_MS)
}

async function login(event) {
  event.preventDefault()
  showError('')
  const body = {
    username: element('username').value.trim(),
    password: element('password').value
  }
  if (!element('otp-field').hidden) {
    body.otp = element('otp').value.trim()
  }
  if (!body.username || !body.password || (body.otp !== undefined && !/^[0-9]{6}$/.test(body.otp))) {
    showError('Enter your username, your password and, if requested, the 6-digit OTP code.')
    return
  }
  element('submit').disabled = true
  try {
    const result = await api('POST', '/api/login', body)
    if (result.status === 200) {
      element('password').value = ''
      element('otp').value = ''
      await refresh()
    } else if (result.status === 429) {
      const minutes = Math.ceil((result.data.retry_after || 60) / 60)
      showError(`Too many failed attempts. Try again in ${minutes} min.`)
    } else if (result.status === 401) {
      showError('Wrong username, password or OTP code.')
    } else if (result.status === 403 && REFUSED[result.data.error]) {
      showRefused(result.data.error)
    } else {
      showError('The login failed. Try again later or contact your administrator.')
    }
  } catch {
    showError('The firewall is not reachable. Check that the VPN is connected.')
  } finally {
    element('submit').disabled = false
  }
}

async function logout() {
  element('logout').disabled = true
  try {
    await api('POST', '/api/logout', {})
  } catch {
    // the status below tells what happened
  } finally {
    element('logout').disabled = false
  }
  await refresh()
}

document.addEventListener('DOMContentLoaded', () => {
  element('login').addEventListener('submit', login)
  element('logout').addEventListener('click', logout)
  element('retry').addEventListener('click', () => {
    show('loading')
    refresh()
  })
  refresh()
})
