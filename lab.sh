#!/usr/bin/env bash
# CVE-2026-111497 (Node2Shell) local lab helper.
set -euo pipefail

cd "$(dirname "$0")"

usage() {
  cat <<'EOF'
Uso: ./lab.sh <comando>

  up              build + sobe alvo vulneravel, alvo corrigido e atacante
  down            derruba tudo e remove volumes
  status          mostra o estado dos containers
  logs            acompanha os logs do alvo vulneravel
  attack          roda o exploit contra 127.0.0.1:3000; por padrao abre um
                  prompt onde VOCE digita o comando (sem argumentos) a cada
                  tentativa. './lab.sh attack --mode id' roda so /usr/bin/id
                  uma vez (nao interativo, bom p/ CI/evidencia)
  attack-loop     tenta o exploit ate 3 vezes (ASLR e probabilistico)
  patched         envia o trigger ao alvo corrigido (espera erro -17)
  check-vuln      envia o trigger ao alvo vulneravel (espera crash)
  shell-attacker  abre shell no container atacante
  shell-target    abre shell no container alvo
  evidence        roda o exploit e salva a saida em evidence/
EOF
}

case "${1:-}" in
  up)
    docker compose up -d --build
    printf '[*] aguardando os alvos ficarem saudaveis'
    for _ in $(seq 1 60); do
      if curl -fsS http://127.0.0.1:3000/health >/dev/null 2>&1 &&
         curl -fsS http://127.0.0.1:3001/health >/dev/null 2>&1; then
        printf ' ok\n'
        break
      fi
      printf '.'
      sleep 0.5
    done
    echo
    echo "[*] alvo vulneravel : http://127.0.0.1:3000  (node 24.22.0)"
    echo "[*] alvo corrigido  : http://127.0.0.1:3001  (node 24.22.1)"
    echo "[*] atacante        : docker compose exec attacker bash"
    ;;
  down)
    docker compose down -v --remove-orphans
    ;;
  status)
    docker compose ps
    ;;
  logs)
    docker compose logs -f --tail=100 target
    ;;
  attack)
    shift || true
    # -t (no -T): modo pick usa um prompt interativo (input());
    # use --mode id se quiser a saida nao-interativa de uma vez
    # (compativel com pipes/CI).
    docker compose exec -t attacker \
      python3 /exploit/node2shell.py --host 127.0.0.1 --port 3000 "$@"
    ;;
  attack-loop)
    shift || true
    for i in 1 2 3; do
      echo "[*] rodada $i/3"
      if docker compose exec -t attacker \
        python3 /exploit/node2shell.py --host 127.0.0.1 --port 3000 "$@"; then
        exit 0
      fi
      echo "[*] sem hit; nova rodada"
    done
    echo "[-] nenhuma rodada obteve RCE; tente novamente" >&2
    exit 1
    ;;
  patched)
    docker compose exec -T attacker \
      python3 /exploit/patched_check.py --host 127.0.0.1 --port 3001 --expect patched
    ;;
  check-vuln)
    docker compose exec -T attacker \
      python3 /exploit/patched_check.py --host 127.0.0.1 --port 3000 --expect vulnerable
    ;;
  shell-attacker)
    docker compose exec attacker bash
    ;;
  shell-target)
    docker compose exec target bash
    ;;
  evidence)
    # --mode id: saida de uma linha reproduzivel, sem tty, para log/CI.
    # Para evidenciar o shell interativo, grave o terminal voce mesmo
    # (ex.: `asciinema rec` ou `script`) enquanto roda `./lab.sh attack`.
    mkdir -p evidence
    stamp="$(date +%Y%m%d-%H%M%S)"
    docker compose exec -T attacker \
      python3 /exploit/node2shell.py --host 127.0.0.1 --port 3000 --mode id \
      2>&1 | tee "evidence/run-${stamp}.log"
    ;;
  *)
    usage
    exit 1
    ;;
esac
