import { useSearchParams } from 'react-router-dom'
import Keys from './settings/Keys'
import Connect from './settings/Connect'
import Budgets from './settings/Budgets'
import Policies from './settings/Policies'
import Alerts from './settings/Alerts'
import Modes from './settings/Modes'

const TABS = [
  { key: 'keys', label: 'API keys', view: <Keys /> },
  { key: 'connect', label: 'Integrations', view: <Connect /> },
  { key: 'budgets', label: 'Budgets', view: <Budgets /> },
  { key: 'policies', label: 'Policies', view: <Policies /> },
  { key: 'modes', label: 'Shadow mode', view: <Modes /> },
  { key: 'alerts', label: 'Alerts', view: <Alerts /> },
]

export default function Settings() {
  const [params, setParams] = useSearchParams()
  const current = TABS.find((t) => t.key === params.get('tab')) || TABS[0]
  return (
    <div className="space-y-5">
      <div role="tablist" aria-label="Settings" className="flex w-fit flex-wrap gap-1 rounded-md border border-line bg-coal p-1">
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={current.key === t.key}
            onClick={() =>
              setParams(
                (p) => {
                  p.set('tab', t.key)
                  return p
                },
                { replace: true },
              )
            }
            className={`rounded px-3 py-1 text-[13px] ${current.key === t.key ? 'bg-lift text-paper' : 'text-dim hover:text-paper'}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel">{current.view}</div>
    </div>
  )
}
