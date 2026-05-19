# ChimangoScan — Artefato de Reprodução

*Medição de Segurança em Larga Escala do Ecossistema de Imagens Docker Hub*

Este repositório é o **artefato de reprodução** do artigo submetido ao SBSeg.
Ele orquestra, ponta a ponta, a pipeline de medição: descoberta e priorização
de imagens do Docker Hub, varredura multi-scanner das imagens priorizadas, e a
regeneração de todas as análises, figuras e tabelas do artigo.

A documentação segue o roteiro de submissão de artefatos da SBC / Simpósio
Brasileiro de Cibersegurança (SBSeg).

---

## Resumo

A pipeline ChimangoScan mede a postura de segurança do ecossistema Docker Hub em
três estágios encadeados:

1. **Descoberta** — varredura distribuída do Docker Hub para coletar
   repositórios e seus *pull counts* (Estágio I, crawler em Go).
2. **Priorização** — construção do grafo IDEA de herança entre camadas de
   imagem e cálculo de uma métrica de *exposure* de cadeia de suprimentos
   (Estágio II + *ranker* de exposure).
3. **Varredura** — execução de seis *scanners* de segurança de container sobre
   as imagens priorizadas, consolidando os *findings* em um esquema único
   (Estágio III).

A descoberta e a priorização vivem no submódulo [`DITector`](stages/DITector); a
varredura, no submódulo [`scanners`](stages/scanners). O artefato que cruza a
fronteira entre os dois é o arquivo `exposure_ranked.jsonl`. Este repositório
fornece os *scripts de orquestração* que executam os estágios em sequência e os
*scripts de análise* que regeneram os números, figuras e tabelas do artigo.

### Selos pretendidos

| Selo | Sigla | Justificativa |
|------|-------|---------------|
| Artefatos Disponíveis | **SeloD** | Código publicamente versionado no GitHub (este repositório e os submódulos). |
| Artefatos Funcionais | **SeloF** | Os estágios podem ser executados; o teste mínimo (Seção *Teste mínimo*) valida o funcionamento ponta a ponta. |
| Experimentos Reprodutíveis | **SeloR** | `orchestration/run_analysis.sh` regenera, a partir da base de dados de varredura, todas as análises, figuras e tabelas do artigo. |

---

## Estrutura do artefato

```
chimangoscan/
├── README.md                     este arquivo (roteiro do artefato)
├── LICENSE                       MIT
├── stages/
│   ├── DITector/                 submódulo — Estágios I+II + ranker de exposure
│   └── scanners/                 submódulo — Estágio III (varredura multi-scanner)
├── orchestration/
│   ├── run_pipeline.sh           executa a pipeline completa ponta a ponta
│   ├── minimal_test.sh           teste mínimo — claim de reprodutibilidade
│   ├── run_analysis.sh           regenera análises/figuras/tabelas do artigo
│   └── make_scanners_config.sh   gera a config do Estágio III a partir do ranking
└── analysis/
    ├── scripts/                  scripts de análise do artigo (regenerate_all.py et al.)
    └── seed-inputs/              insumos não recomputados da base (caches, CDF de crawl)
```

> **Não incluído neste repositório:** o `main.tex` e o PDF do artigo. O texto
> do artigo é mantido em um repositório privado separado. Este artefato contém
> apenas o código e os dados que produzem os resultados do artigo.

---

## Informações básicas

A pipeline tem dois perfis de execução com requisitos distintos.

**Teste mínimo** — valida o funcionamento ponta a ponta; roda em uma única
máquina em algumas dezenas de minutos.

| Recurso | Requisito mínimo |
|---------|------------------|
| CPU | 4 núcleos |
| Memória | 8 GB |
| Disco | 20 GB livres (imagens Docker + bancos) |
| Rede | acesso à internet (Docker Hub) |
| Tempo | ~20–45 min |

**Execução completa** — reproduz a medição em escala do artigo; concebida para
operação distribuída em múltiplas máquinas ao longo de dias.

| Recurso | Recomendado |
|---------|-------------|
| CPU | 16+ núcleos por nó |
| Memória | 32+ GB por nó (heap do Neo4j configurável) |
| Disco | centenas de GB (datasets MongoDB/Neo4j + artefatos de varredura) |
| Tempo | dias (crawl + build + varredura) |

---

## Dependências

| Componente | Versão | Usado por |
|------------|--------|-----------|
| Go | ≥ 1.21 | Estágios I e II (`stages/DITector`) |
| Python | ≥ 3.10 | ranker de exposure, Estágio III, scripts de análise |
| [uv](https://docs.astral.sh/uv/) | recente | gerenciador de dependências do `stages/scanners` |
| Docker + Docker Compose | recente | MongoDB, Neo4j, *scanners* containerizados |
| MongoDB | 6+ | repositórios e tags (Estágio I/II) |
| Neo4j | 5+ | grafo IDEA de camadas (Estágio II) |
| matplotlib, numpy | recentes | scripts de figuras (`analysis/`) |

Sistema operacional de referência: **Linux x86-64**. Os *scanners* do Estágio III
são imagens Docker fixadas por digest — não há instalação de ferramentas no
sistema hospedeiro.

Bibliotecas Python para a etapa de análise:

```bash
python3 -m pip install matplotlib numpy
```

---

## Preocupações com segurança

- O crawler do Estágio I exige contas do Docker Hub (gratuitas bastam),
  fornecidas em `stages/DITector/accounts.json`. **Esse arquivo nunca deve ser
  versionado** — já está coberto pelo `.gitignore`.
- O Estágio III **baixa e executa imagens de container de terceiros**. Os
  *scanners* dinâmicos sobem o container alvo. Recomenda-se executar a varredura
  em uma máquina isolada/descartável, nunca em um host de produção.
- Nenhum dos passos exige privilégios além do acesso ao *daemon* Docker.

---

## Instalação

```bash
# 1. Clonar o repositório com os submódulos (DITector e scanners)
git clone --recurse-submodules https://github.com/ChimangoScan/chimangoscan.git
cd chimangoscan

# Se já tiver clonado sem --recurse-submodules:
git submodule update --init --recursive

# 2. Subir a infraestrutura de bancos (MongoDB + Neo4j)
cd stages/DITector
docker compose up -d mongodb neo4j
cp config_template.yaml config.yaml          # ajuste se necessário

# 3. Fornecer as contas do Docker Hub para o crawler
cat > accounts.json <<'EOF'
[{"username": "SEU_USUARIO", "password": "SUA_SENHA"}]
EOF
cd ../..

# 4. Resolver as dependências Python do Estágio III
cd stages/scanners && uv sync && cd ../..
```

---

## Teste mínimo

O teste mínimo é a **reivindicação (claim)** de reprodutibilidade deste
artefato:

> *A pipeline ChimangoScan executa de ponta a ponta — descoberta no Docker Hub,
> priorização e varredura multi-scanner — produzindo um relatório consolidado.*

O script `orchestration/minimal_test.sh` valida essa claim **sem** varrer todo o
Docker Hub. Ele:

1. **rastreia** o Docker Hub por um tempo curto, restrito a alguns prefixos de
   *namespace* (padrão: `a,b,c`) — Estágio I, em miniatura;
2. **constrói** o grafo IDEA de camadas para os repositórios descobertos —
   Estágio II;
3. roda o **ranker**, que ordena todos os repositórios encontrados por *pull
   count* e por *exposure* de cadeia de suprimentos;
4. seleciona o **top 10** repositórios mais expostos e executa os seis
   *scanners* padrão sobre eles — Estágio III;
5. **verifica** que o relatório consolidado do corpus (`report.html`,
   `summary.json`, `analysis.md`) foi produzido.

```bash
orchestration/minimal_test.sh
# opções: --prefixes a,b,c   --crawl-duration 5m   --top 10
```

Ao final, em caso de sucesso, o script imprime `MINIMAL TEST PASSED` e o caminho
dos artefatos gerados em `artifacts/`. Tempo esperado: ~20–45 min, dominado pelo
*pull* e pela varredura das 10 imagens.

---

## Experimentos

### Pipeline completa (medição em escala)

Reproduz a medição do artigo. Em produção, o crawl e a varredura são executados
de forma distribuída ao longo de dias; o script abaixo executa a sequência em
uma máquina:

```bash
orchestration/run_pipeline.sh \
  --seed a \
  --crawl-duration 24h \
  --threshold 1000 \
  --workers 20
```

Estágios executados, em ordem:

1. **Estágio I** — `go run main.go crawl` descobre repositórios no Docker Hub.
2. **Estágio II** — `go run main.go build` constrói o grafo IDEA no Neo4j.
3. **Ranker** — `compute_exposure_ranking.py` gera
   `artifacts/exposure_ranked.jsonl` (uma linha JSON por repositório, ordenada
   por *exposure* decrescente).
4. **Estágio III** — `scanners seed` + `scanners run` varrem as imagens
   priorizadas com os seis *scanners*; `scanners report`/`analyze` consolidam o
   corpus.

O único artefato que cruza a fronteira entre os Estágios I/II e o Estágio III é
`exposure_ranked.jsonl` — o *contrato* da pipeline.

### Regeneração das análises, figuras e tabelas do artigo

Todo número de tabela e toda figura orientada a dados do artigo derivam da base
SQLite de resultados de varredura. Para regenerá-los:

```bash
orchestration/run_analysis.sh --db /caminho/para/ditector-good.db
# stages individuais: --stage analysis | figures | tables
# validação amostral: --sample 100000
```

Isso executa `analysis/scripts/regenerate_all.py`, que em uma passagem
*read-only* sobre a base recomputa todas as JSONs de análise, regenera as
figuras (`artifacts/analysis/figures/*.pdf`) e emite `table_values.json` com
todos os valores das tabelas do artigo. A base é aberta em modo somente-leitura;
o passo é idempotente e nunca edita o texto do artigo.

---

## Ambiente de avaliação

O artefato foi desenvolvido e exercitado em workstations Linux x86-64 com Docker.
O teste mínimo é autocontido e não exige infraestrutura distribuída. A pipeline
completa foi operada em um conjunto de máquinas Linux coordenadas via os
mecanismos de *claim* atômico do MongoDB (Estágios I/II) e a fila de trabalho do
Estágio III.

---

## Licença

Distribuído sob a licença MIT — ver [`LICENSE`](LICENSE). Os submódulos
[`DITector`](https://github.com/ChimangoScan/DITector) e
[`scanners`](https://github.com/ChimangoScan/scanners) carregam suas próprias
licenças. O `DITector` é um *fork* de
[NSSL-SJTU/DITector](https://github.com/NSSL-SJTU/DITector); o método de
descoberta e do grafo IDEA é inspirado no artigo *Dr. Docker* (WWW '25), com
implementação original dos autores deste trabalho.
