#!/usr/bin/env python3
"""Follows one PipelineRun in the Tekton Dashboard and saves a screenshot of
each stage of it.

    record.py --dashboard http://127.0.0.1:18097 --namespace default \\
        --run run-your-app-demo --frames frames/

The dashboard is reached through mask-proxy.py, so --run is the name as the
proxy shows it. Firefox must already be running with --marionette.

There is no live connection to watch (the proxy refuses WebSockets), so the
page is loaded afresh for every frame, opened on whichever task is running at
that moment. The result is a time-lapse: one frame every few seconds while the
build runs.
"""
import argparse
import json
import os
import time
import urllib.request

from firefox import Firefox


def get(dashboard, path):
    with urllib.request.urlopen(dashboard + path, timeout=30) as resp:
        return json.load(resp)


def run_state(dashboard, namespace, run):
    """Returns (done, succeeded, the task to show)."""
    try:
        pr = get(dashboard, f'/apis/tekton.dev/v1/namespaces/{namespace}/pipelineruns/{run}')
    except Exception:
        return None
    cond = (pr.get('status', {}).get('conditions') or [{}])[0]
    done = cond.get('status') in ('True', 'False')
    trs = get(dashboard, f'/apis/tekton.dev/v1/namespaces/{namespace}/taskruns/'
                         f'?labelSelector=tekton.dev%2FpipelineRun%3D{run}')['items']
    trs.sort(key=lambda t: t['metadata']['creationTimestamp'])
    current = None
    for tr in trs:
        current = tr['metadata']['labels'].get('tekton.dev/pipelineTask')
        if not tr.get('status', {}).get('completionTime'):
            break
    return done, cond.get('status') == 'True', current


def settle(ff, text, timeout=20):
    """Waits until the page shows text and has stopped growing."""
    deadline, last = time.time() + timeout, -1
    while time.time() < deadline:
        body = ff.js('return document.body ? document.body.innerText : ""')
        if text in body and len(body) == last:
            return True
        last = len(body)
        time.sleep(0.6)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dashboard', required=True)
    parser.add_argument('--namespace', default='default')
    parser.add_argument('--run', required=True)
    parser.add_argument('--frames', required=True)
    parser.add_argument('--interval', type=float, default=4.0, help='seconds between frames')
    parser.add_argument('--final-task', default='verify-image-policy')
    parser.add_argument('--final-step', default='report')
    parser.add_argument('--width', type=int, default=1360)
    parser.add_argument('--height', type=int, default=1010)
    args = parser.parse_args()
    os.makedirs(args.frames, exist_ok=True)

    ff = Firefox()
    ff.resize(args.width, args.height)
    count = 0

    def frame(url, text, hold=1):
        nonlocal count
        ff.go('about:blank')
        ff.go(url)
        settle(ff, text)
        for _ in range(hold):
            count += 1
            ff.screenshot(os.path.join(args.frames, f'{count:04d}.png'))

    runs = f'{args.dashboard}/#/namespaces/{args.namespace}/pipelineruns'
    page = f'{runs}/{args.run}'

    # The list of runs, until this one appears in it.
    deadline = time.time() + 180
    while run_state(args.dashboard, args.namespace, args.run) is None:
        if time.time() > deadline:
            raise SystemExit(f'PipelineRun {args.run} never appeared')
        frame(runs, 'PipelineRuns')
        time.sleep(args.interval)
    frame(runs, args.run, hold=2)

    # The run itself, opened on the task that is running.
    deadline = time.time() + 1800
    succeeded = False
    while time.time() < deadline:
        state = run_state(args.dashboard, args.namespace, args.run)
        if state is None:
            time.sleep(2)
            continue
        done, succeeded, task = state
        if done:
            break
        frame(f'{page}?pipelineTask={task}&view=logs' if task else page, args.run)
        time.sleep(args.interval)

    # The finished run from the top, then what its last step printed.
    frame(page, 'Succeeded' if succeeded else 'Failed', hold=2)
    frame(f'{page}?pipelineTask={args.final_task}&step={args.final_step}&view=logs', args.final_task, hold=4)
    print(f'{count} frames; run {"succeeded" if succeeded else "did not succeed"}')
    raise SystemExit(0 if succeeded else 1)


if __name__ == '__main__':
    main()
