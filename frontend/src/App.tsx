import { FormEvent, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Check,
  Clipboard,
  Clock3,
  Copy,
  Database,
  KeyRound,
  Languages,
  Menu,
  Moon,
  Monitor,
  Network,
  Plus,
  Pencil,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  Sun,
  TerminalSquare,
  X,
  XCircle,
} from 'lucide-react'
import { getInitialLanguage, Language, translate } from './i18n'

type NodeStatus = 'healthy' | 'degraded' | 'offline'

type ServerNode = {
  id: string
  name: string
  host: string
  port: number
  environment: string
  status: NodeStatus
  latency: number | null
  lastSeen: string
  hostKey: string | null
}

type Session = {
  sessionId: string
  serverId: string
  token: string
  command: string
  link: string
  port: number
  expiresAt: number
  maxExpiresAt: number
}

type NetworkInterface = {
  index: number | null
  name: string
  ip: string
  isTunnel: boolean
  selectable: boolean
}

const initialNodes: ServerNode[] = [
  { id: 'tokyo-api', name: 'TOKYO_API', host: '203.0.113.12', port: 22, environment: 'PRODUCTION', status: 'healthy', latency: 42, lastSeen: '2 min ago', hostKey: null },
  { id: 'singapore-worker', name: 'SINGAPORE_WORKER', host: '203.0.113.28', port: 22, environment: 'PRODUCTION', status: 'healthy', latency: 58, lastSeen: '4 min ago', hostKey: null },
  { id: 'staging-box', name: 'STAGING_BOX', host: '198.51.100.24', port: 2222, environment: 'STAGING', status: 'degraded', latency: 92, lastSeen: '18 min ago', hostKey: null },
  { id: 'local-dev', name: 'LOCAL_DEV', host: '127.0.0.1', port: 22, environment: 'DEVELOPMENT', status: 'offline', latency: null, lastSeen: 'yesterday', hostKey: null },
]

function formatTime(seconds: number) {
  const safeSeconds = Math.max(0, seconds)
  const minutes = Math.floor(safeSeconds / 60).toString().padStart(2, '0')
  const remainder = Math.floor(safeSeconds % 60).toString().padStart(2, '0')
  return `${minutes}:${remainder}`
}

function maskHost(host: string) {
  const parts = host.split('.')
  if (parts.length === 4 && parts.every((part) => /^\d+$/.test(part))) {
    return `${parts[0]}.**.**.${parts[3]}`
  }
  return host
}

async function createSessionFromHost(serverId: string): Promise<Session> {
  const response = await fetch(`/api/servers/${encodeURIComponent(serverId)}/ssh-sessions`, { method: 'POST' })
  if (!response.ok) {
    if (response.status === 412) throw new Error('host-key-required')
    throw new Error(`session creation failed: ${response.status}`)
  }
  const payload = await response.json() as { session_id: string; server_id: string; port: number; token: string; connect_command: string; connect_uri: string; expires_at: number; max_expires_at: number }
  return {
    sessionId: payload.session_id,
    serverId: payload.server_id,
    port: payload.port,
    token: payload.token,
    command: payload.connect_command,
    link: payload.connect_uri,
    expiresAt: payload.expires_at * 1000,
    maxExpiresAt: payload.max_expires_at * 1000,
  }
}

async function fetchSessionFromHost(serverId: string): Promise<Session | null> {
  const response = await fetch(`/api/servers/${encodeURIComponent(serverId)}/ssh-sessions`)
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`session lookup failed: ${response.status}`)
  const payload = await response.json() as { session_id: string; server_id: string; port: number; token: string; connect_command: string; connect_uri: string; expires_at: number; max_expires_at: number }
  return {
    sessionId: payload.session_id,
    serverId: payload.server_id,
    port: payload.port,
    token: payload.token,
    command: payload.connect_command,
    link: payload.connect_uri,
    expiresAt: payload.expires_at * 1000,
    maxExpiresAt: payload.max_expires_at * 1000,
  }
}

async function fetchServersFromHost(): Promise<ServerNode[]> {
  const response = await fetch('/api/servers')
  if (!response.ok) throw new Error(`server list failed: ${response.status}`)
  const payload = await response.json() as Array<{ id: string; name: string; host: string; port: number; environment: string; status: NodeStatus; latency: number | null; last_seen: string; host_key: string | null }>
  return payload.map((server) => ({
    id: server.id,
    name: server.name,
    host: server.host,
    port: server.port,
    environment: server.environment,
    status: server.status,
    latency: server.latency,
    lastSeen: server.last_seen,
    hostKey: server.host_key,
  }))
}

async function fetchNetworkInterfaces(): Promise<NetworkInterface[]> {
  const response = await fetch('/api/network/interfaces')
  if (!response.ok) throw new Error(`network interfaces failed: ${response.status}`)
  const payload = await response.json() as Array<{ index: number | null; name: string; ip: string; is_tunnel: boolean; selectable: boolean }>
  return payload.map((item) => ({ index: item.index, name: item.name, ip: item.ip, isTunnel: item.is_tunnel, selectable: item.selectable }))
}

async function fetchNetworkSettings(): Promise<number | null> {
  const response = await fetch('/api/settings/network')
  if (!response.ok) throw new Error(`network settings failed: ${response.status}`)
  const payload = await response.json() as { interface_index: number | null }
  return payload.interface_index
}

async function renewSessionFromHost(session: Session): Promise<Session> {
  const response = await fetch(`/api/ssh-sessions/${encodeURIComponent(session.sessionId)}/renew`, { method: 'POST' })
  if (!response.ok) throw new Error(`session renewal failed: ${response.status}`)
  const payload = await response.json() as { expires_at: number; max_expires_at: number }
  return { ...session, expiresAt: payload.expires_at * 1000, maxExpiresAt: payload.max_expires_at * 1000 }
}

function revokeSessionOnHost(session: Session | null) {
  if (!session || session.sessionId.startsWith('mock-')) return
  void fetch(`/api/ssh-sessions/${encodeURIComponent(session.sessionId)}`, { method: 'POST' })
}

function App() {
  const [nodes, setNodes] = useState(initialNodes)
  const [selectedId, setSelectedId] = useState(initialNodes[0].id)
  const [appPort] = useState(() => window.location.port || '0')
  const [query, setQuery] = useState('')
  const [sessions, setSessions] = useState<Record<string, Session>>({})
  const [now, setNow] = useState(Date.now())
  const [isAddOpen, setIsAddOpen] = useState(false)
  const [editingNode, setEditingNode] = useState<ServerNode | null>(null)
  const [editingUsername, setEditingUsername] = useState('')
  const [isSidebarOpen, setIsSidebarOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const [notice, setNotice] = useState('')
  const [auth, setAuth] = useState<{ configured: boolean; authenticated: boolean } | null>(null)
  const [authPassword, setAuthPassword] = useState('')
  const [authConfirm, setAuthConfirm] = useState('')
  const [authNotice, setAuthNotice] = useState('')
  const [language, setLanguage] = useState<Language>(getInitialLanguage)
  const [theme, setTheme] = useState<'dark' | 'light'>(() => window.localStorage.getItem('atimesh-theme') === 'light' ? 'light' : 'dark')
  const [view, setView] = useState<'dashboard' | 'settings'>('dashboard')
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterface[]>([])
  const [networkSelection, setNetworkSelection] = useState('auto')
  const [networkLoading, setNetworkLoading] = useState(false)
  const [networkSaving, setNetworkSaving] = useState(false)
  const t = (key: Parameters<typeof translate>[1]) => translate(language, key)

  const selectedNode = nodes.find((node) => node.id === selectedId) ?? nodes[0] ?? {
    id: 'empty', name: 'NO NODE SELECTED', host: '--', port: 0,
    environment: 'LOCAL', status: 'offline' as NodeStatus, latency: null, lastSeen: '--',
  }
  const hasSelectedNode = nodes.length > 0
  const session = hasSelectedNode ? sessions[selectedNode.id] ?? null : null
  const filteredNodes = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return nodes
    return nodes.filter((node) => `${node.name} ${node.host} ${node.environment}`.toLowerCase().includes(normalizedQuery))
  }, [nodes, query])
  const remainingSeconds = session ? Math.ceil((session.expiresAt - now) / 1000) : 0
  const progress = session ? Math.max(0, Math.min(100, (remainingSeconds / 600) * 100)) : 0

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (session && hasSelectedNode && remainingSeconds <= 0) {
      setSessions((current) => { const next = { ...current }; delete next[selectedNode.id]; return next })
      setNotice(t('sessionExpired'))
    }
  }, [remainingSeconds, session, hasSelectedNode, selectedNode.id, language])

  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(''), 2800)
    return () => window.clearTimeout(timer)
  }, [notice])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('atimesh-theme', theme)
  }, [theme])

  useEffect(() => {
    void fetch('/api/auth/status')
      .then((response) => response.json() as Promise<{ configured: boolean; authenticated: boolean }>)
      .then(setAuth)
      .catch(() => setAuth({ configured: false, authenticated: true }))
  }, [])

  useEffect(() => {
    if (!auth?.authenticated) return
    void fetchServersFromHost()
      .then((serverList) => {
        setNodes(serverList)
        setSelectedId((current) => serverList.some((server) => server.id === current) ? current : (serverList[0]?.id ?? ''))
        void Promise.all(serverList.map(async (server) => {
          try {
            return [server.id, await fetchSessionFromHost(server.id)] as const
          } catch {
            return [server.id, null] as const
          }
        })).then((entries) => {
          const restored = entries.reduce<Record<string, Session>>((accumulator, [serverId, restoredSession]) => {
            if (restoredSession) accumulator[serverId] = restoredSession
            return accumulator
          }, {})
          setSessions(restored)
        })
      })
      .catch(() => undefined)
    setNetworkLoading(true)
    void Promise.all([fetchNetworkInterfaces(), fetchNetworkSettings()])
      .then(([interfaces, preference]) => {
        setNetworkInterfaces(interfaces)
        setNetworkSelection(preference === null ? 'auto' : String(preference))
      })
      .catch(() => setNetworkInterfaces([]))
      .finally(() => setNetworkLoading(false))
  }, [auth?.authenticated])

  useEffect(() => {
    window.localStorage.setItem('atimesh-language', language)
  }, [language])

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!auth?.configured && authPassword !== authConfirm) {
      setAuthNotice(t('passwordMismatch'))
      return
    }
    const endpoint = auth?.configured ? '/api/auth/login' : '/api/auth/setup'
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password: authPassword }),
      })
      if (!response.ok) throw new Error('auth failed')
      setAuth({ configured: true, authenticated: true })
      setAuthPassword('')
      setAuthConfirm('')
      setAuthNotice('')
    } catch {
      setAuthNotice(t('authFailed'))
    }
  }

  async function lockConsole() {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => undefined)
    setAuth((current) => current ? { ...current, authenticated: false } : current)
  }

  if (!auth) {
    return <div className="auth-shell"><div className="auth-card"><div className="brand-mark"><TerminalSquare size={19} /></div><h1>ATimeSsh</h1><p>Loading secure console…</p></div></div>
  }

  if (!auth.authenticated) {
    return (
      <div className="auth-shell">
        <form className="auth-card" onSubmit={submitAuth}>
          <div className="auth-brand"><div className="brand-mark"><KeyRound size={19} /></div><span>ATimeSsh</span></div>
          <div className="auth-kicker">{auth.configured ? t('loginSecurityPassword') : t('setupSecurityPassword')}</div>
          <h1>{auth.configured ? t('unlock') : t('setupAndUnlock')}</h1>
          <p>{t('securityPasswordHint')}</p>
          <label>{t('securityPassword')}<input autoFocus type="password" minLength={8} value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} /></label>
          {!auth.configured && <label>{t('confirmPassword')}<input type="password" minLength={8} value={authConfirm} onChange={(event) => setAuthConfirm(event.target.value)} /></label>}
          {authNotice && <div className="auth-error">{authNotice}</div>}
          <button className="primary-button auth-submit" type="submit">{auth.configured ? t('unlock') : t('setupAndUnlock')} <ShieldCheck size={16} /></button>
          <button className="auth-language" type="button" onClick={() => setLanguage(language === 'zh' ? 'en' : 'zh')}><Languages size={14} /> {language === 'zh' ? 'EN' : '中文'}</button>
        </form>
      </div>
    )
  }

  async function generateSession() {
    if (!hasSelectedNode) return
    revokeSessionOnHost(session)
    try {
      const nextSession = await createSessionFromHost(selectedNode.id)
      setSessions((current) => ({ ...current, [selectedNode.id]: nextSession }))
      setNotice(t('sessionCreatedNotice'))
    } catch (error) {
      setNotice(error instanceof Error && error.message === 'host-key-required' ? t('hostKeyRequired') : t('sessionCreationFailed'))
    }
  }

  async function renewSession() {
    if (!session) return
    let nextSession = session
    try {
      nextSession = session.sessionId.startsWith('mock-')
        ? { ...session, expiresAt: Math.min(session.expiresAt + 10 * 60 * 1000, session.maxExpiresAt) }
        : await renewSessionFromHost(session)
    } catch {
      setNotice(t('sessionExpired'))
      return
    }
    setSessions((current) => ({ ...current, [selectedNode.id]: nextSession }))
    setNotice(nextSession.expiresAt === session.maxExpiresAt ? t('sessionMaxRenewed') : t('sessionRenewed'))
  }

  async function copyCommand() {
    if (!session) return
    await navigator.clipboard?.writeText(session.link)
    setCopied(true)
    setNotice(t('commandCopied'))
    window.setTimeout(() => setCopied(false), 1800)
  }

  async function addNode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const name = String(data.get('name') ?? '').trim().toUpperCase().replace(/\s+/g, '_')
    const host = String(data.get('host') ?? '').trim()
    const port = Number(data.get('port') ?? 22)
    const username = String(data.get('username') ?? '').trim()
    const password = String(data.get('password') ?? '')
    if (!name || !host || !port) return
    setNotice(t('nodeSaving'))
    const newNode: ServerNode = {
      id: `${name.toLowerCase()}-${Date.now()}`,
      name,
      host,
      port,
      environment: String(data.get('environment') ?? 'STAGING').toUpperCase(),
      status: 'healthy',
      latency: 64,
      lastSeen: 'just now',
      hostKey: null,
    }
    try {
      const response = await fetch(`/api/servers/${encodeURIComponent(newNode.id)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name, host, port, username, password }),
      })
      if (!response.ok) {
        const detail = (await response.text()).trim()
        throw new Error(response.status === 409 ? 'host key changed' : detail || 'server registry unavailable')
      }
      const serverList = await fetchServersFromHost()
      setNodes(serverList)
      setSelectedId(newNode.id)
      setIsAddOpen(false)
      setNotice(t('nodeSavedVerified'))
      return
    } catch (error) {
      setNotice(error instanceof Error && error.message === 'host key changed' ? t('hostKeyChangedOnSave') : `${t('nodeSaveFailed')}: ${error instanceof Error ? error.message : ''}`)
      return
    }
  }

  async function editNode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!editingNode) return
    const data = new FormData(event.currentTarget)
    const body = {
      name: String(data.get('name') ?? '').trim().toUpperCase().replace(/\s+/g, '_'),
      host: String(data.get('host') ?? '').trim(),
      port: Number(data.get('port') ?? 22),
      username: String(data.get('username') ?? '').trim(),
      password: String(data.get('password') ?? ''),
    }
    setNotice(t('nodeSaving'))
    try {
      const response = await fetch(`/api/servers/${encodeURIComponent(editingNode.id)}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      if (!response.ok) throw new Error((await response.text()).trim() || 'server update failed')
      const serverList = await fetchServersFromHost()
      setNodes(serverList)
      setIsAddOpen(false)
      setEditingNode(null)
      setNotice(t('nodeUpdated'))
    } catch (error) {
      setNotice(`${t('nodeUpdateFailed')}: ${error instanceof Error ? error.message : ''}`)
    }
  }

  async function saveNetworkSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setNetworkSaving(true)
    try {
      const response = await fetch('/api/settings/network', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ interface_index: networkSelection === 'auto' ? null : Number(networkSelection) }),
      })
      if (!response.ok) throw new Error('network settings unavailable')
      setNotice(t('networkSettingsSaved'))
    } catch {
      setNotice(t('networkSettingsFailed'))
    } finally {
      setNetworkSaving(false)
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><TerminalSquare size={19} strokeWidth={2.4} /></div>
          <div>
            <div className="brand-name">ATimeSsh</div>
            <div className="brand-subtitle">CONTROL ROOM / SSH SESSION MANAGER</div>
          </div>
        </div>
        <div className="topbar-meta">
          <span className="service-state"><span className="pulse-dot" /> {t('serviceOnline')}</span>
          <span className="port-label">PORT {appPort}</span>
          <button className="utility-button" onClick={() => setLanguage(language === 'zh' ? 'en' : 'zh')} title={language === 'zh' ? 'Switch to English' : '切换中文'}><Languages size={15} /><span>{language === 'zh' ? 'EN' : '中'}</span></button>
          <button className="utility-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title={theme === 'dark' ? 'Light mode' : 'Dark mode'}>{theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}<span>{theme === 'dark' ? 'LIGHT' : 'DARK'}</span></button>
          <button className="icon-button mobile-menu" onClick={() => setIsSidebarOpen(true)} aria-label="打开节点列表"><Menu size={18} /></button>
          <button className="avatar" onClick={lockConsole} title={t('logout')}>A</button>
        </div>
      </header>

      <div className="workspace">
        <aside className={`sidebar ${isSidebarOpen ? 'sidebar-open' : ''}`}>
          <div className="sidebar-heading"><span>{t('nodes')}</span><strong>{nodes.length.toString().padStart(2, '0')}</strong><button className="icon-button sidebar-close" onClick={() => setIsSidebarOpen(false)} aria-label="Close node list"><X size={17} /></button></div>
          <label className="search-box"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('searchPlaceholder')} /></label>
          <button className="add-node-link" onClick={() => { setView('dashboard'); setIsAddOpen(true) }}><Plus size={15} /> {t('addNode')}</button>
          <div className="node-list" aria-label="服务器节点">
            {filteredNodes.map((node) => (
              <button key={node.id} className={`node-item ${node.id === selectedId ? 'selected' : ''}`} onClick={() => { setView('dashboard'); setSelectedId(node.id); setIsSidebarOpen(false) }}>
                <span className={`status-dot ${node.status}`} />
                <span className="node-copy"><strong>{node.name}</strong><small>{maskHost(node.host)}:{node.port}</small><em>{node.status === 'offline' ? t('offline') : node.status.toUpperCase()}</em></span>
              </button>
            ))}
            {filteredNodes.length === 0 && <div className="empty-search">{t('noMatchingNodes')}</div>}
          </div>
          <button className={`settings-nav ${view === 'settings' ? 'selected' : ''}`} onClick={() => setView('settings')}><Settings size={15} /> {t('settings')}</button>
        </aside>
        {isSidebarOpen && <button className="sidebar-scrim" onClick={() => setIsSidebarOpen(false)} aria-label="关闭节点列表" />}

        <main className="main-content">
          {view === 'settings' ? <SettingsView t={t} interfaces={networkInterfaces} selection={networkSelection} loading={networkLoading} saving={networkSaving} onSelectionChange={setNetworkSelection} onSubmit={saveNetworkSettings} /> : hasSelectedNode ? <>
          <section className="node-header">
            <div>
              <div className="eyebrow"><span className={`status-dot ${selectedNode.status}`} /> {t('node')} / {selectedNode.environment}</div>
              <h1>{selectedNode.name}</h1>
              <p>{maskHost(selectedNode.host)} <span>·</span> {t('lastSeen')} {selectedNode.lastSeen}</p>
            </div>
            <div className="node-header-actions"><button className="secondary-button" onClick={async () => { try { const response = await fetch(`/api/servers/${encodeURIComponent(selectedNode.id)}`); const details = await response.json() as { username: string }; setEditingUsername(details.username); setEditingNode(selectedNode); setIsAddOpen(true) } catch { setNotice(t('nodeUpdateFailed')) } }}><Pencil size={15} /> {t('editNode')}</button><button className="primary-button" onClick={generateSession} disabled={!selectedNode.hostKey}><KeyRound size={16} /> {t('generateTempLink')}</button></div>
          </section>

          <section className="metrics-grid">
            <Metric icon={<Network size={16} />} label={t('connection')} value={selectedNode.status === 'offline' ? t('offline') : t('connected')} tone={selectedNode.status === 'healthy' ? 'green' : selectedNode.status === 'degraded' ? 'amber' : 'muted'} />
            <Metric icon={<Activity size={16} />} label={t('latency')} value={selectedNode.latency ? `${selectedNode.latency} ms` : '--'} />
            <Metric icon={<Database size={16} />} label={t('hostKey')} value={selectedNode.hostKey ? t('verified') : t('pending')} />
            <Metric icon={<Monitor size={16} />} label={t('sshPort')} value={selectedNode.port.toString()} />
          </section>

          <section className="session-panel">
            <div className="panel-heading"><div><span className="eyebrow">{t('temporaryChannel')}</span><h2>{t('relaySession')}</h2></div>{session ? <span className="session-badge"><span className="pulse-dot" /> {t('active')}</span> : <span className="session-badge inactive">{t('inactive')}</span>}</div>
            {session ? <>
              <div className="command-row"><div className="command-copy"><code>{session.link}</code><small>SSH COMMAND / {session.command}</small><small>PASSWORD / {session.token}</small></div><button className="copy-button" onClick={copyCommand}>{copied ? <Check size={16} /> : <Copy size={16} />}<span>{copied ? 'COPIED' : 'COPY'}</span></button></div>
              <div className="ttl-row"><div><span className="eyebrow">{t('timeToLive')}</span><div className="countdown">{formatTime(remainingSeconds)}</div></div><div className="ttl-caption">{t('expiresAt')} {new Date(session.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}<br /><span>{t('renewalCapped')}</span></div></div>
              <div className="progress-track"><div className="progress-value" style={{ width: `${progress}%` }} /></div>
              <div className="session-actions"><button className="secondary-button" onClick={copyCommand}><Clipboard size={15} /> {t('copy')}</button><button className="secondary-button" onClick={renewSession}><RefreshCw size={15} /> {t('renew')}</button><button className="danger-button" onClick={() => { revokeSessionOnHost(session); setSessions((current) => { const next = { ...current }; delete next[selectedNode.id]; return next }); setNotice(t('sessionRevoked')) }}><XCircle size={15} /> {t('revoke')}</button></div>
            </> : <div className="session-empty"><Clock3 size={23} /><div><strong>{t('noActiveSession')}</strong><span>{t('createSecureChannel')}</span></div><button className="secondary-button" onClick={generateSession}><Plus size={15} /> {t('createSession')}</button></div>}
          </section>

          <section className="audit-section"><div className="section-label"><span>{t('auditTrail')}</span><button className="text-button"><RefreshCw size={13} /> {t('refresh')}</button></div><div className="audit-list"><Audit time="14:21:18" text={t('sessionCreated')} /><Audit time="14:21:20" text={t('hostVerified')} /><Audit time="14:22:06" text={t('clipboardRequested')} /></div></section>
          <footer className="main-footer"><span>ATimeSsh / {t('localInfrastructure')}</span><span>v0.1.0 · {t('secureMode')}</span></footer>
          </> : <HomeView t={t} onAddNode={() => { setView('dashboard'); setIsAddOpen(true) }} />}
        </main>
      </div>

      {notice && <div className="toast"><Check size={15} /> {notice}</div>}
      {isAddOpen && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) { setIsAddOpen(false); setEditingNode(null) } }}><div className="modal"><div className="modal-header"><div><span className="eyebrow">{t('nodeRegistry')}</span><h2>{editingNode ? t('editNode') : t('addNewNode')}</h2></div><button className="icon-button" onClick={() => { setIsAddOpen(false); setEditingNode(null) }} aria-label="Close dialog"><X size={18} /></button></div><form onSubmit={editingNode ? editNode : addNode}><label>{t('nodeName')}<input name="name" defaultValue={editingNode?.name} placeholder="e.g. FRANKFURT_API" autoFocus required /></label><div className="form-row host-port-row"><label>{t('hostIp')}<input name="host" defaultValue={editingNode?.host} placeholder="203.0.113.40" required /></label><label>{t('sshPort')}<input name="port" type="number" defaultValue={editingNode?.port ?? 22} min="1" max="65535" required /></label></div><label>{t('username')}<input name="username" defaultValue={editingNode ? editingUsername : undefined} placeholder={t('encryptedLocally')} required /></label><label>{t('password')}<input name="password" type="password" placeholder={editingNode ? t('passwordOptional') : t('encryptedLocally')} required={!editingNode} /></label><div className="form-note"><ShieldCheck size={15} /> {editingNode ? t('editCredentialsHint') : t('credentialsNeverShown')}</div><button className="primary-button modal-submit" type="submit">{editingNode ? <Pencil size={16} /> : <Plus size={16} />} {editingNode ? t('saveChanges') : t('addNode')}</button></form></div></div>}
    </div>
  )
}

function SettingsView({
  t,
  interfaces,
  selection,
  loading,
  saving,
  onSelectionChange,
  onSubmit,
}: {
  t: (key: Parameters<typeof translate>[1]) => string
  interfaces: NetworkInterface[]
  selection: string
  loading: boolean
  saving: boolean
  onSelectionChange: (value: string) => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  return (
    <div className="settings-view">
      <section className="settings-header">
        <div>
          <div className="eyebrow"><Settings size={14} /> {t('settings')}</div>
          <h1>{t('networkSettings')}</h1>
          <p>{t('networkSettingsDescription')}</p>
        </div>
        <div className="settings-state"><span className="pulse-dot" /> {selection === 'auto' ? t('automaticSelection') : t('manualSelection')}</div>
      </section>
      <form className="settings-form" onSubmit={onSubmit}>
        <section className="settings-section">
          <div className="settings-section-heading"><div><span className="eyebrow">NETWORK EGRESS</span><h2>{t('networkInterface')}</h2></div><span className="settings-caption">{t('newSessionsUseSetting')}</span></div>
          <label className={`network-option ${selection === 'auto' ? 'selected' : ''}`}>
            <input type="radio" name="network-interface" value="auto" checked={selection === 'auto'} onChange={(event) => onSelectionChange(event.target.value)} />
            <span className="network-option-mark" />
            <span className="network-option-copy"><strong>{t('automaticSelection')}</strong><small>{t('autoNetworkDescription')}</small></span>
          </label>
          {loading && <div className="settings-loading">{t('loading')}</div>}
          {!loading && interfaces.map((item) => {
            const value = item.index === null ? `${item.name}-${item.ip}` : String(item.index)
            const checked = item.index !== null && selection === value
            return (
              <label key={value} className={`network-option ${checked ? 'selected' : ''} ${!item.selectable ? 'disabled' : ''}`}>
                <input type="radio" name="network-interface" value={value} checked={checked} disabled={!item.selectable} onChange={(event) => onSelectionChange(event.target.value)} />
                <span className="network-option-mark" />
                <span className="network-option-copy"><strong>{item.name}</strong><small>{item.ip || '--'} · {t('interfaceIndex')} {item.index ?? '--'}</small></span>
                <span className={`network-option-badge ${item.isTunnel ? 'virtual' : ''}`}>{item.isTunnel ? t('virtualInterface') : item.selectable ? t('physicalInterface') : t('unavailable')}</span>
              </label>
            )
          })}
          {!loading && interfaces.length === 0 && <div className="settings-empty"><Network size={18} /> {t('networkInterfacesUnavailable')}</div>}
        </section>
        <div className="settings-actions"><span>{t('settingsApplyHint')}</span><button className="primary-button" type="submit" disabled={saving || loading}><Check size={15} /> {saving ? t('saving') : t('saveNetworkSettings')}</button></div>
      </form>
      <footer className="main-footer"><span>ATimeSsh / {t('localInfrastructure')}</span><span>v0.1.0 · {t('secureMode')}</span></footer>
    </div>
  )
}

function HomeView({ t, onAddNode }: { t: (key: Parameters<typeof translate>[1]) => string; onAddNode: () => void }) {
  return (
    <div className="home-view">
      <section className="home-hero">
        <div className="home-hero-copy">
          <div className="eyebrow"><span className="pulse-dot" /> {t('homeKicker')}</div>
          <h1>{t('homeTitle')}</h1>
          <p>{t('homeDescription')}</p>
          <button className="primary-button home-cta" onClick={onAddNode}><Plus size={16} /> {t('homeAddFirstNode')}</button>
        </div>
        <div className="home-signal" aria-hidden="true">
          <div className="signal-ring signal-ring-large" />
          <div className="signal-ring signal-ring-small" />
          <div className="signal-core"><TerminalSquare size={25} /></div>
          <span className="signal-label signal-label-top">LOCAL / 127.0.0.1</span>
          <span className="signal-label signal-label-bottom">READY FOR NODE REGISTRATION</span>
        </div>
      </section>

      <section className="home-capabilities" aria-label={t('homeKicker')}>
        <HomeCapability icon={<Network size={18} />} title={t('homeLocalTitle')} description={t('homeLocalDescription')} />
        <HomeCapability icon={<KeyRound size={18} />} title={t('homeSessionTitle')} description={t('homeSessionDescription')} />
        <HomeCapability icon={<ShieldCheck size={18} />} title={t('homeCredentialTitle')} description={t('homeCredentialDescription')} />
      </section>

      <section className="home-workflow">
        <div className="section-label"><span>{t('homeWorkflow')}</span><span>ATIMESSH / 01</span></div>
        <div className="workflow-steps">
          <HomeStep number="01" title={t('homeStepOne')} description={t('homeStepOneDescription')} />
          <HomeStep number="02" title={t('homeStepTwo')} description={t('homeStepTwoDescription')} />
          <HomeStep number="03" title={t('homeStepThree')} description={t('homeStepThreeDescription')} />
        </div>
      </section>

      <footer className="main-footer"><span>ATimeSsh / {t('localInfrastructure')}</span><span>v0.1.0 · {t('secureMode')}</span></footer>
    </div>
  )
}

function HomeCapability({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return <article className="home-capability"><div className="home-capability-icon">{icon}</div><div><h2>{title}</h2><p>{description}</p></div></article>
}

function HomeStep({ number, title, description }: { number: string; title: string; description: string }) {
  return <article className="workflow-step"><span className="workflow-number">{number}</span><div><h3>{title}</h3><p>{description}</p></div></article>
}

function Metric({ icon, label, value, tone = 'default' }: { icon: React.ReactNode; label: string; value: string; tone?: 'default' | 'green' | 'amber' | 'muted' }) {
  return <div className="metric"><div className="metric-label">{icon}{label}</div><strong className={`tone-${tone}`}>{value}</strong></div>
}

function Audit({ time, text }: { time: string; text: string }) {
  return <div className="audit-row"><span>{time}</span><span className="audit-marker" /><p>{text}</p></div>
}

export default App
