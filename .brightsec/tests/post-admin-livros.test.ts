import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

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

test('POST /admin/livros', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'excessive_data_exposure', 'sqli', 'xss', 'bopla', 'date_manipulation'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/admin/livros`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        idPrecificacao: 123,
        data: '2023-10-01',
        preco: 29.99,
        titulo: 'Sample Book Title',
        isbn: '123-4567890123',
        paginas: 300,
        sinopse: 'This is a sample synopsis of the book.',
        codigoBarra: '123456789012',
        dimensoes: {
          altura: 20,
          largura: 15,
          profundidade: 2
        },
        editora: 'Sample Publisher',
        edicao: '1st Edition',
        imagem: [{
          url: 'http://example.com/image1.jpg'
        }],
        autor: [{
          nome: 'Author Name'
        }],
        categoria: [{
          nome: 'Category Name'
        }]
      })
    });
});
