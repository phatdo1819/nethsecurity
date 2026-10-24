/*
 * Copyright (C) 2026 Nethesis S.r.l.
 * SPDX-License-Identifier: GPL-2.0-only
 */

'use strict'

const REFRESH_MS = 30000
const sections = ['loading', 'unavailable', 'login', 'session']
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
