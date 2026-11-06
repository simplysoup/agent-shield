"""Explicit opt-in CLI. Plan mode never makes model calls."""
import argparse
from datetime import datetime,timezone
import json,os
from pathlib import Path
from .heldout import load_heldout,load_benign,ROOT, _read
from .adaptive import OpenAIAttacker,run_adaptive,summarize_adaptive
from .real_agent import evaluate_case

def build_defender(model, provider='openai'):
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError("Install optional dependencies: pip install -e '.[agent,models]'") from exc
    if provider == 'groq':
        key = os.getenv('GROQ_API_KEY')
        if not key:
            raise RuntimeError('GROQ_API_KEY required for Groq defender')
        return ChatOpenAI(model=model, api_key=key,
                          base_url=os.getenv('GROQ_BASE_URL', 'https://api.groq.com/openai/v1'),
                          temperature=0, max_retries=1)
    if provider != 'openai':
        raise ValueError('Unsupported defender provider: '+provider)
    return ChatOpenAI(model=model, use_responses_api=True,
                      reasoning={'effort':'low'}, max_retries=1)


def load_environment():
    try:
        from dotenv import load_dotenv
    except ImportError:
        return  # Plan mode works without optional model dependencies.
    load_dotenv()

def main(argv=None):
    load_environment()
    p=argparse.ArgumentParser(description='AgentShield opt-in adaptive red-team evaluation')
    p.add_argument('--phase',choices=['plan','development','frozen','benign'],default='plan')
    p.add_argument('--attacker',default=os.getenv('AGENTSHIELD_ATTACKER_MODEL','gpt-6-luna'))
    p.add_argument('--defender',default=os.getenv('AGENTSHIELD_DEFENDER_MODEL','llama-3.1-8b-instant'))
    p.add_argument('--defender-provider',choices=['openai','groq'],default=os.getenv('AGENTSHIELD_DEFENDER_PROVIDER','groq'))
    p.add_argument('--configurations',nargs='+',choices=['policy','layered','vulnerable'],default=['policy'])
    p.add_argument('--attempts',type=int,default=3)
    p.add_argument('--max-cases',type=int,default=6)
    p.add_argument('--max-trials',type=int,default=500)
    p.add_argument('--max-errors',type=int,default=10)
    p.add_argument('--output')
    p.add_argument('--fixture-file',type=Path,help='explicit attack fixture JSONL (frozen phase only)')
    p.add_argument('--exposure-mode',choices=['preloaded','natural'],default='preloaded',
                   help='preloaded guarantees identical prompt exposure; natural tests tool retrieval')
    p.add_argument('--unpaired',action='store_true',help='legacy mode: generate a separate payload per configuration')
    p.add_argument('--execute',action='store_true',help='explicitly authorize paid inference')
    a=p.parse_args(argv)
    if a.max_cases<1 or a.max_trials<1 or not 1<=a.attempts<=10: p.error('invalid budgets')
    if a.fixture_file and a.phase!='frozen': p.error('--fixture-file requires --phase frozen')
    if a.phase=='frozen' and a.attempts!=1: p.error('frozen requires --attempts 1')
    cases=(load_heldout(a.fixture_file) if a.fixture_file else load_benign() if a.phase=='benign' else _read(ROOT/'development'/'adaptive.jsonl') if a.phase=='development' else load_heldout())[:a.max_cases]
    trials=len(cases)*len(a.configurations)*(a.attempts if a.phase=='development' else 1)
    if trials>a.max_trials: p.error('trial budget exceeded')
    manifest={'phase':a.phase,'attacker':a.attacker,'defender':a.defender,'defender_provider':a.defender_provider,
              'cases':len(cases),'configurations':a.configurations,'maximum_trials':trials,'paired':not a.unpaired,'exposure_mode':a.exposure_mode,
              'note':'No model calls unless --execute is provided; costs vary with token usage.'}
    if a.phase=='plan' or not a.execute:
        print(json.dumps(manifest,indent=2))
        if a.phase!='plan': print('Not executed; add --execute to authorize model calls.')
        return 0
    if a.phase=='development' and not os.getenv('OPENAI_API_KEY'): p.error('OPENAI_API_KEY required for attacker generation')
    output=Path(a.output or f"results/{a.phase}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl")
    if output.exists(): p.error('output already exists')
    if a.defender_provider=='groq' and not os.getenv('GROQ_API_KEY'): p.error('GROQ_API_KEY required')
    print(json.dumps({'provider_routing': {'attacker': {'provider': 'openai', 'model': a.attacker}, 'defender': {'provider': a.defender_provider, 'model': a.defender, 'endpoint': os.getenv('GROQ_BASE_URL', 'https://api.groq.com/openai/v1') if a.defender_provider == 'groq' else 'OpenAI default'}}, 'credentials': 'redacted'}), flush=True)
    defender=build_defender(a.defender,a.defender_provider)
    if a.phase=='benign':
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x') as f:
            for config in a.configurations:
                for case in cases:
                    result=evaluate_case(case,defender,config)
                    f.write(json.dumps(vars(result))+'\n');f.flush()
        print(json.dumps({'output':str(output),'trials':trials}))
    else:
        attacker=OpenAIAttacker(a.attacker) if a.phase=='development' else None
        results=run_adaptive(cases,attacker,defender,output,configurations=a.configurations,
            attempts=a.attempts if a.phase=='development' else 1,phase=a.phase,
            max_trials=a.max_trials,max_errors=a.max_errors,paired=not a.unpaired,
            exposure_mode=a.exposure_mode)
        print(json.dumps({'output':str(output),'summary':summarize_adaptive(results),
                          'attacker_usage':getattr(attacker,'usage',None)},indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
