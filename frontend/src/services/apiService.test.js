import apiService from './apiService';

describe('apiService statistics', () => {
  test('does not expose demo statistics as production metrics', async () => {
    await expect(apiService.getStatistics()).resolves.toBeNull();
  });
});
