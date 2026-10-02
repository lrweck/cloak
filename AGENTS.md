# AGENTS.md — cloak

## Dependências

**Sempre a versão mais recente.** Ao precisar de uma versão nova, pegue a latest. Não
pinar em major/minor antiga "para ser estável": uma pin velha é um gate rodando regras
de uma release que já não recebe correcao.

Corollary: nada de versão duplicada em dois lugares. `go-version-file: go.mod` em vez
de `go-version: '1.27'` literal, e `golangci-lint-action` com `version: latest` em vez
de `go install ...@vX.Y.Z`.

**Nunca instalar golangci-lint localmente.** Ele roda direto no runner via
`golangci/golangci-lint-action`. Instalar na máquina cria uma segunda cópia com versão
diferente da que o CI usa, e é exatamente essa diferença que faz um resultado local
não servir para nada.

## Zero dependências é um contrato, não um acidente

`go.mod` tem uma linha e um module path. Nada entra na library — nem para testar. Os 36
testes de README usam `testing` puro justamente porque um deles verifica o arquivo que
anuncia a contagem de dependencias.

Comparacao com outras bibliotecas vive em `bench/compare/`, que e um modulo separado
por isso. Codecov, testify, x/tools: nada disso entra aqui.

Quando uma API esta depreciada, a alternativa com dependencia *nao* e a resposta
(`parser.ParseDir` → `x/tools/go/packages`). A resposta e o reescrita com a stdlib.

## Numeros em documentacao

Toda tabela de README vem de um unico `go test -bench .` run. Duas tabelas de runs
diferentes produzem deltas que nao fecham, e a prosa herda a diferenca. Ao mexer em
numeros, regerar tudo e conferir programaticamente.

## Escopo

Só faça o que foi pedido. Se algo parece útil mas ninguém pediu, **pergunte** — não
construa. Trabalho a mais custa tempo do revisor e mascara o que era importante.

Antes de escrever um teste, um helper ou um check: ele é exigido por algo, ou é
speculação? Um check que nenhum bug conhecido pode provocar é o pior tipo: parece
segurança e não é. Antes de aceitar um check como útil, mutar o código que ele
protege e ver se ele falha — se não falhar, não está protegendo nada.

Da mesma forma: um teste só vale o que a direção que ele **não** prova custa. Dizer o
que um teste não cobre é parte de escrevê-lo, não uma nota de rodapé.

## Commits

Um por mudanca. O corpo explica o *por que* e o que foi descartado, nao o diff.