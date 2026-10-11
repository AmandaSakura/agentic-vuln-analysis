"""Standard PGFPlots vector charts from exact recorded data, with no new runs."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]
REPORT = ROOT/"docs/reports/cv_agent_technical_report_2026-10-01"
FIGURES = REPORT/"figures"
BUILD = ROOT/"artifacts/technical_report_20261001/figure_build"
D = json.loads((REPORT/"data/report_data.json").read_text())
PREAMBLE = r'''\documentclass[tikz,border=5pt]{standalone}
\usepackage{fontspec}
\setmainfont{TeX Gyre Termes}
\setsansfont{TeX Gyre Heros}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usetikzlibrary{patterns,positioning,arrows.meta}
\definecolor{blue}{HTML}{0072B2}
\definecolor{green}{HTML}{009E73}
\definecolor{orange}{HTML}{E69F00}
\definecolor{red}{HTML}{D55E00}
\definecolor{grey}{HTML}{8D9399}
\pgfplotsset{every axis/.append style={width=8.1cm,height=5.3cm,
font=\small,axis lines=left,axis line style={grey},tick align=outside,
enlarge x limits=.18,ymajorgrids=true,grid style={grey!18},
tick label style={font=\small},label style={font=\small},
nodes near coords style={font=\small,/pgf/number format/fixed,/pgf/number format/precision=2,/pgf/number format/1000 sep={,}},clip=false}}
\begin{document}
'''


def axis(options, plots, position=""):
    return r"\begin{axis}["+position+options+"]\n"+plots+"\n"+r"\end{axis}"+"\n"


def bars(values, color="blue"):
    return r"\addplot[fill="+color+",draw=none] coordinates {" + " ".join(f"({i},{v})" for i,v in enumerate(values)) + "};\n"


def save(name, body):
    tex = FIGURES/f"{name}.tex"
    tex.write_text(PREAMBLE + r"\begin{tikzpicture}"+"\n"+body+r"\end{tikzpicture}"+"\n"+r"\end{document}"+"\n")
    with (BUILD/f"{name}.stdout.log").open("w") as log:
        completed = subprocess.run(["xelatex","-no-shell-escape","-interaction=nonstopmode","-halt-on-error",
            f"-output-directory={BUILD}",str(tex)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
    if completed.returncode:
        raise RuntimeError(f"Figure compilation failed: {name}")
    (FIGURES/f"{name}.pdf").write_bytes((BUILD/f"{name}.pdf").read_bytes())


def main():
    BUILD.mkdir(parents=True,exist_ok=True)
    layers=sorted(D["by_layer_files"],key=lambda k:D["by_layer_files"][k])
    opts="xbar,height=7.2cm,ymin=-.7,ymax="+str(len(layers)-.3)+",ytick={"+",".join(map(str,range(len(layers))))+"},yticklabels={"+",".join(x.replace("_"," ") for x in layers)+"},"
    body=""
    for k,key,label in [(0,"by_layer_files","Python files"),(1,"by_layer_lines","Physical source lines")]:
        vals=[D[key][x] for x in layers]
        plot=r"\addplot[fill=blue,draw=none] coordinates {"+" ".join(f"({v},{i})" for i,v in enumerate(vals))+"};"
        body+=axis(opts+f"xlabel={{{label}}},xmin=0,xmax={max(vals)*1.25},nodes near coords,point meta=x",plot,
                   "at={("+str(k*8.8)+"cm,0)},anchor=south west,")
    save("code_footprint",body)
    names="xtick={0,1,2},xticklabels={Baseline,Repair 1,Final},"
    body=axis("ybar,"+names+"ymin=0,ymax=3100,ylabel={Passed test cases},nodes near coords",bars([2560,2682,2684]))
    body+=axis("ybar,"+names+"ymin=0,ymax=550,ylabel={Observed suite seconds},nodes near coords",
               bars([478.78,414.94,414.2],"grey"),"at={(8.8cm,0)},anchor=south west,")
    save("regression_progress",body)
    values=[round(1000*c["wall_seconds"],2) for c in D["cli_cases"]]
    labels="Literal mode,Unknown mode,Zero candidates,Parse error,Byte limit,Missing root,Other language"
    plot=r"\addplot[fill=blue,draw=none] coordinates {"+" ".join(f"({v},{6-i})" for i,v in enumerate(values))+"};"
    body=axis("xbar,width=10cm,height=6.2cm,xmin=0,xmax=340,ymin=-.7,ymax=6.7,ytick={6,5,4,3,2,1,0},yticklabels={"+labels+
              "},xlabel={CLI process wall time (ms)},nodes near coords,point meta=x",plot)
    body+=r"\node[align=left,anchor=west,font=\small] at (10.5cm,2.4cm) {7/7 artifact deliveries\\3 COMPLETED\\2 PARTIAL\\2 BLOCKED\\0 model requests\\0 target executions};"
    save("cli_outcomes",body)
    body=axis("ybar,xtick={0,1,2},xticklabels={Source parse,Static validation,Property proof},"
        r"ymin=0,ymax=105,ylabel={Descriptive fraction (\%)},nodes near coords",bars([80,50,25]))
    body+=axis("ybar,xtick={0,1},xticklabels={REFUTED,UNKNOWN},ymin=0,ymax=4,ylabel={Candidate count (N=4)},nodes near coords",
               bars([1,3],"grey"),"at={(8.8cm,0)},anchor=south west,")
    save("cli_evidence_denominators",body)
    phase_names="xtick={0,1,2},xticklabels={M0 phase 1,M0 phase 2,E-iter},"
    body=axis("ybar,"+phase_names+"ymin=0,ymax=38,ylabel={API requests},nodes near coords",bars([32,14,26]))
    body+=axis("ybar,"+phase_names+"ymin=0,ymax=220000,ylabel={Reported tokens},scaled y ticks=false,nodes near coords",
               bars([191177,90153,166482],"orange"),"at={(8.8cm,0)},anchor=south west,")
    save("historical_usage",body)
    body=axis("ybar,xtick={0,1},xticklabels={Request cap,Token cap},ymin=0,ymax=100,"
              r"ylabel={Authorized cap consumed (\%)},nodes near coords",bars([round(72/210*100,2),round(447812/2500000*100,2)]))
    body+=r"\node[align=left,anchor=west,font=\small] at (9.2cm,2cm) {72 / 210 requests\\447,812 / 2,500,000 tokens\\Unused: 138 requests\\Unused: 2,052,188 tokens\\Unused budget is not authorization};"
    save("budget_utilization",body)
    cell_names="xtick={0,1,2,3},xticklabels={Dev a,Dev b,Callback a,Callback b},"
    body=axis("ybar,"+cell_names+"ymin=0,ymax=54000,ylabel={Reported tokens},scaled y ticks=false,nodes near coords",
               bars([c["tokens"] for c in D["eiter_cases"]]))
    body+=axis("ybar,"+cell_names+"ymin=0,ymax=1.6,ylabel={Physical scenario attempts},ytick={0,1},nodes near coords",
               bars([1,1,1,1],"orange"),"at={(8.8cm,0)},anchor=south west,")
    save("eiter_cells",body)
    body=axis("ybar,xtick={0,1,2,3},xticklabels={Task 1,Task 2,Task 3,Task 4},ymin=0,ymax=3100,"
        "ylabel={Complete certificate bytes},nodes near coords",bars([2500,1000,1000,1000])+
        r"\draw[red,dashed,thick] (axis cs:-.5,2048)--(axis cs:3.5,2048);"+
        r"\node[red,anchor=west,font=\scriptsize] at (axis cs:1.4,2220) {first share: 2048};")
    body+=r"\node[align=left,anchor=west,font=\small] at (9.1cm,2.4cm) {Required: 5,500 bytes\\Diagnostic reserve: 256 bytes\\Total cap: 8,192 bytes\\Remaining: 2,436 bytes\\First-task equal-share shortfall: 452 bytes};"
    save("certificate_budget",body)
    body=axis("ybar,xtick={0,1},xticklabels={Required passed,Conditional disabled},ymin=0,ymax=36,"
              "ylabel={Acceptance items (N=34)},nodes near coords",bars([31,3],"green"))
    body+=r"\node[align=left,anchor=west,font=\small] at (9.1cm,2.2cm) {GP0: PASS\\GP1: PASS for static profile\\GP2: NOT ENABLED\\GP3: NOT MEASURED\\GP4: NOT MEASURED};"
    save("acceptance_gates",body)
    print(json.dumps({"backend":"PGFPlots","vector_figures":9,"new_experiments":0}))


if __name__ == "__main__": main()
