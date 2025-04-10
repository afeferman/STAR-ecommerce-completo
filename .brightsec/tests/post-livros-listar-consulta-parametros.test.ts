import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /livros/listar/consulta/parametros', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'excessive_data_exposure', 'csrf', 'business_constraint_bypass', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/livros/listar/consulta/parametros`,
      query: {
        page: '0',
        size: '10'
      },
      body: {
        precoMenor: 10.0,
        precoMaior: 100.0,
        dataMenor: '2023-01-01',
        dataMaior: '2023-12-31',
        titulo: 'Example Title',
        isbn: '1234567890',
        paginas: 200,
        editora: 'Example Editora',
        edicao: '1st Edition',
        autorIds: [1, 2],
        categoriaIds: [1, 2],
        alturaMaior: 30.0,
        alturaMenor: 10.0,
        larguraMaior: 20.0,
        larguraMenor: 5.0,
        pesoMaior: 2.0,
        pesoMenor: 0.5,
        profundidadeMaior: 15.0,
        profundidadeMenor: 5.0
      }
    });
});
