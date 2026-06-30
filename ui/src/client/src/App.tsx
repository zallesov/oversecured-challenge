import { LogOut, RefreshCw, ShieldCheck, UploadCloud } from 'lucide-react';
import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState
} from 'react';
import { api, ApiError, clearToken, getToken, setToken, upsertById, type Run, type User } from './api';
import { RunDetail } from './components/RunDetail';
import { RunList } from './components/RunList';

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unexpected error';
}

function AuthGate({ onAuthenticated }: { onAuthenticated: (user: User) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = mode === 'login' ? await api.login(email, password) : await api.register(email, password);
      setToken(response.token);
      onAuthenticated(response.user);
    } catch (nextError) {
      setError(messageFor(nextError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-screen">
      <section className="auth-panel" aria-labelledby="auth-heading">
        <div className="brand-mark">
          <ShieldCheck size={26} aria-hidden="true" />
          <span>Oversecured SAST</span>
        </div>
        <h1 id="auth-heading">{mode === 'login' ? 'Sign in' : 'Create account'}</h1>
        <p>Access APK scans, pipeline telemetry, and security findings.</p>

        <div className="segmented-control" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            className={mode === 'login' ? 'active' : ''}
            onClick={() => setMode('login')}
            aria-selected={mode === 'login'}
            role="tab"
          >
            Sign in
          </button>
          <button
            type="button"
            className={mode === 'register' ? 'active' : ''}
            onClick={() => setMode('register')}
            aria-selected={mode === 'register'}
            role="tab"
          >
            Register
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          <label>
            <span>Email</span>
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              required
            />
          </label>
          <label>
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              minLength={8}
              required
            />
          </label>
          {error ? <div className="inline-alert">{error}</div> : null}
          <button className="primary-button" type="submit" disabled={busy}>
            {busy ? <RefreshCw size={16} aria-hidden="true" className="spin" /> : <ShieldCheck size={16} aria-hidden="true" />}
            {mode === 'login' ? 'Sign in' : 'Register'}
          </button>
        </form>
      </section>
    </main>
  );
}

type AppRoute =
  | { kind: 'runs' }
  | { kind: 'run-detail'; runId: string };

function parseRoute(pathname: string): AppRoute {
  const normalized = pathname.replace(/\/+$/, '') || '/';
  const match = normalized.match(/^\/runs\/([^/]+)$/);
  if (match) {
    return { kind: 'run-detail', runId: decodeURIComponent(match[1]) };
  }
  return { kind: 'runs' };
}

function UploadPanel({
  onUploaded
}: {
  onUploaded: (run: Run) => void;
}) {
  const formRef = useRef<HTMLFormElement | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError('Choose an APK file first.');
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const run = await api.uploadRun(file);
      formRef.current?.reset();
      setFile(null);
      onUploaded(run);
    } catch (nextError) {
      setError(messageFor(nextError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel upload-panel" aria-labelledby="upload-heading">
      <div className="panel-heading">
        <div>
          <h2 id="upload-heading">Upload APK</h2>
          <p>Start a scan from a signed or debug APK package.</p>
        </div>
      </div>
      <form ref={formRef} className="upload-form" onSubmit={submit}>
        <label className="file-drop">
          <UploadCloud size={22} aria-hidden="true" />
          <span>{file ? file.name : 'Choose .apk file'}</span>
          <input
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </label>
        {error ? <div className="inline-alert">{error}</div> : null}
        <button className="primary-button" type="submit" disabled={busy || !file}>
          {busy ? <RefreshCw size={16} aria-hidden="true" className="spin" /> : <UploadCloud size={16} aria-hidden="true" />}
          Start scan
        </button>
      </form>
    </section>
  );
}

export default function App() {
  const [booting, setBooting] = useState(true);
  const [user, setUser] = useState<User | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [loadingRuns, setLoadingRuns] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pathname, setPathname] = useState(() => window.location.pathname);

  const route = useMemo(() => parseRoute(pathname), [pathname]);
  const selectedRunId = route.kind === 'run-detail' ? route.runId : null;
  const navigate = useCallback((nextPath: string, options?: { replace?: boolean }) => {
    if (options?.replace) {
      window.history.replaceState({}, '', nextPath);
    } else {
      window.history.pushState({}, '', nextPath);
    }
    setPathname(window.location.pathname);
  }, []);

  const loadRuns = useCallback(async () => {
    setLoadingRuns(true);
    setError(null);
    try {
      const nextRuns = await api.listRuns();
      setRuns(nextRuns);
    } catch (nextError) {
      setError(messageFor(nextError));
    } finally {
      setLoadingRuns(false);
    }
  }, []);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      const token = getToken();
      if (!token) {
        setBooting(false);
        return;
      }
      try {
        const nextUser = await api.me();
        if (!cancelled) {
          setUser(nextUser);
        }
      } catch {
        clearToken();
      } finally {
        if (!cancelled) {
          setBooting(false);
        }
      }
    }
    boot();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (user) {
      void loadRuns();
    }
  }, [loadRuns, user]);

  // Live runs subscription — opens after initial load, closed on logout/unmount
  useEffect(() => {
    if (!user) {
      return;
    }

    let cancelled = false;
    let unsub: (() => Promise<void>) | null = null;

    api
      .subscribeRuns((action, run) => {
        if (cancelled) return;
        setRuns((prev) => {
          const next = upsertById(prev, run, action);
          // Keep newest-first (matches listRuns sort: -created)
          return action === 'delete'
            ? next
            : [...next].sort((a, b) => {
                const ta = a.createdAt ?? '';
                const tb = b.createdAt ?? '';
                return tb < ta ? -1 : tb > ta ? 1 : 0;
              });
        });
      })
      .then((fn) => {
        if (cancelled) {
          void fn();
        } else {
          unsub = fn;
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(messageFor(e));
      });

    return () => {
      cancelled = true;
      if (unsub) {
        void unsub();
      }
    };
  }, [user]);

  useEffect(() => {
    if (!user) {
      return;
    }
    if (pathname === '/' || pathname === '') {
      navigate('/runs', { replace: true });
    }
  }, [navigate, pathname, user]);

  function handleUploaded(run: Run) {
    setRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
    navigate(`/runs/${run.id}`);
  }

  function handleRunUpdated(run: Run) {
    setRuns((current) => current.map((item) => (item.id === run.id ? { ...item, ...run } : item)));
  }

  function logout() {
    clearToken();
    setUser(null);
    setRuns([]);
    navigate('/runs', { replace: true });
  }

  if (booting) {
    return (
      <main className="boot-screen">
        <RefreshCw size={22} className="spin" aria-hidden="true" />
        <span>Loading dashboard</span>
      </main>
    );
  }

  if (!user) {
    return <AuthGate onAuthenticated={setUser} />;
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <div className="brand-mark">
            <ShieldCheck size={25} aria-hidden="true" />
            <span>Oversecured SAST</span>
          </div>
          <p>APK scan operations dashboard</p>
        </div>
        <div className="header-actions">
          <span className="user-email">{user.email}</span>
          <button className="secondary-button" type="button" onClick={logout}>
            <LogOut size={16} aria-hidden="true" />
            Sign out
          </button>
        </div>
      </header>

      {error ? <div className="global-alert">{error}</div> : null}

      <main className="dashboard-layout">
        <aside className="dashboard-sidebar" aria-label="Scan controls">
          <UploadPanel onUploaded={handleUploaded} />
          <RunList
            runs={runs}
            selectedRunId={selectedRunId}
            loading={loadingRuns}
            onSelectRun={(id) => navigate(`/runs/${id}`)}
          />
        </aside>
        <RunDetail
          runId={selectedRunId}
          onRunUpdated={handleRunUpdated}
          onGoToRuns={route.kind === 'run-detail' ? () => navigate('/runs') : undefined}
        />
      </main>
    </div>
  );
}
