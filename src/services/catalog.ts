import { id, now, json, requireValue } from '../core.js';
import type { Store, Row } from '../db.js';
import type { ProductInput, Line } from '../schemas.js';
export class Catalog {
  constructor(public db: Store, private publicUrl = 'http://localhost:3000') {}
  dto(row: Row) {
    const data = JSON.parse(row.data);
    const images: string[] = Array.isArray(data.images) ? data.images : Array.isArray(data.image_urls) ? data.image_urls : data.image_url ? [data.image_url] : [];
    return { ...data, images, image_urls: images, image_url: images[0] || '', id: row.id, sku: row.sku, price: row.price, stock: row.stock - row.reserved, version: row.version, created_at: row.created_at, updated_at: row.updated_at };
  }
  get(productId: string, includeArchived = false): Row {
    const row = this.db.one(`SELECT * FROM products WHERE id=?${includeArchived ? '' : ' AND archived=0'}`, productId);
    requireValue(row, 404, 'Product unavailable.', 'PRODUCT_UNAVAILABLE'); return row;
  }
  list() { return this.db.all('SELECT * FROM products WHERE archived=0 ORDER BY created_at DESC,id').map(row => this.dto(row)); }
  validateImage(url: string): string {
    requireValue(!url.startsWith('data:'), 400, 'Upload the image first; data URLs are not accepted.');
    const publicOrigin = new URL(this.publicUrl);
    let parsed: URL | undefined;
    try { parsed = new URL(url, publicOrigin); } catch { /* handled below */ }
    const internal = parsed && parsed.origin === publicOrigin.origin && !parsed.search && !parsed.hash
      ? /^\/api\/media\/([a-zA-Z0-9-]+)$/.exec(parsed.pathname)
      : null;
    if (internal) {
      requireValue(this.db.one("SELECT id FROM media WHERE id=? AND purpose='product'", internal[1]), 400, 'Invalid product image.');
      this.db.run('UPDATE media SET attached_at=? WHERE id=?', now(), internal[1]);
      return `${publicOrigin.origin}${parsed!.pathname}`;
    } else {
      requireValue(parsed?.protocol === 'https:' && !parsed.username && !parsed.password, 400, 'Images must be uploaded or use an HTTPS URL.');
      return url;
    }
  }
  create(input: ProductInput, actor: string, seedId?: string) {
    return this.db.tx(() => {
      const { image_urls: imageUrlsAlias, ...productFields } = input;
      const rawImages = input.images ?? imageUrlsAlias ?? (input.image_url ? [input.image_url] : []);
      const images = rawImages.map(image => this.validateImage(image));
      requireValue(new Set(input.colors.map(c => c.name)).size === input.colors.length, 400, 'Color names must be unique.');
      requireValue(!this.db.one('SELECT id FROM products WHERE sku=?', input.sku.trim()), 409, 'SKU already exists.', 'SKU_EXISTS');
      const productId = seedId || id(), timestamp = now();
      const product = { ...productFields, images, image_url: images[0] || '' };
      this.db.run('INSERT INTO products(id,sku,price,stock,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?)', productId, input.sku.trim(), input.price, input.stock, json(product), timestamp, timestamp);
      this.db.audit(actor, 'product_created', productId);
      this.db.event('product_created', productId, 'public', null, 1);
      return this.dto(this.get(productId));
    });
  }
  update(productId: string, input: Partial<ProductInput> & { expected_version: number }, actor: string) {
    return this.db.tx(() => {
      const old = this.get(productId);
      requireValue(old.version === input.expected_version, 409, 'Product changed. Refresh and try again.', 'VERSION_CONFLICT');
      const { expected_version, image_urls: imageUrlsAlias, ...bodyUpdates } = input;
      const aliasImages = bodyUpdates.images ?? imageUrlsAlias;
      const updates = { ...bodyUpdates, ...(aliasImages !== undefined ? { images: aliasImages } : {}) };
      // Browser stock is available stock. Absolute stock edits need the version;
      // reservations and purchases both increment it.
      const previous = JSON.parse(old.data);
      const next = { ...previous, ...updates };
      const previousImages: string[] = Array.isArray(previous.images)
        ? previous.images
        : Array.isArray(previous.image_urls) ? previous.image_urls
        : previous.image_url ? [previous.image_url] : [];
      let rawImages: string[];
      if (updates.images !== undefined) {
        rawImages = updates.images;
      } else if (updates.image_url !== undefined) {
        // Legacy single-cover edits update the cover but retain the rest of the gallery.
        rawImages = updates.image_url ? [updates.image_url, ...previousImages.filter(image => image !== updates.image_url)] : [];
      } else {
        rawImages = previousImages;
      }
      const images = rawImages.map(image => this.validateImage(image));
      next.images = images;
      next.image_url = images[0] || '';
      requireValue(new Set(next.colors.map((c: { name: string }) => c.name)).size === next.colors.length, 400, 'Color names must be unique.');
      requireValue(!this.db.one('SELECT id FROM products WHERE sku=? AND id<>?', next.sku.trim(), productId), 409, 'SKU already exists.', 'SKU_EXISTS');
      const stock = updates.stock === undefined ? old.stock : updates.stock + old.reserved;
      this.db.run('UPDATE products SET sku=?,price=?,stock=?,data=?,version=version+1,updated_at=? WHERE id=?', next.sku.trim(), next.price, stock, json(next), now(), productId);
      if (stock !== old.stock) this.movement(productId, stock-old.stock, 'Product editor stock change', actor, id());
      this.db.audit(actor, 'product_updated', productId, { fields: Object.keys(updates) });
      return this.changed(productId);
    });
  }
  archive(productId: string, actor: string) {
    return this.db.tx(() => {
      const old = this.get(productId);
      this.db.run('UPDATE products SET archived=1,version=version+1,updated_at=? WHERE id=?', now(), productId);
      this.db.audit(actor, 'product_archived', productId);
      this.db.event('product_deleted', productId, 'public', null, old.version + 1);
      return { id: productId, version: old.version + 1 };
    });
  }
  changed(productId: string) {
    const row = this.get(productId, true);
    this.db.event(row.archived ? 'product_deleted' : 'product_updated', productId, 'public', null, row.version);
    return this.dto(row);
  }
  movement(productId: string, delta: number, reason: string, actor: string | null, operation: string) {
    this.db.run('INSERT INTO stock_movements VALUES (?,?,?,?,?,?,?)', id(), productId, delta, reason, actor, operation, now());
  }
  adjust(productId: string, delta: number, reason: string, actor: string, key: string, expectedVersion?: number) {
    return this.db.tx(() => {
      const scope = `inventory:${actor}:${productId}`, body = { delta, reason, expectedVersion };
      if (this.db.prior(scope, key, body)) return this.dto(this.get(productId));
      const row = this.get(productId);
      requireValue(expectedVersion === undefined || row.version === expectedVersion, 409, 'Stock changed. Refresh and try again.', 'VERSION_CONFLICT');
      requireValue(row.stock + delta >= row.reserved, 409, 'This adjustment would consume reserved stock.', 'STOCK_CONFLICT');
      this.db.run('UPDATE products SET stock=stock+?,version=version+1,updated_at=? WHERE id=?', delta, now(), productId);
      this.movement(productId, delta, reason, actor, id());
      this.db.audit(actor, 'stock_adjusted', productId, { delta, reason });
      this.db.remember(scope, key, body, productId);
      return this.changed(productId);
    });
  }
  lines(lines: Line[], checkStock = true) {
    const byProduct = new Map<string, number>(), identities = new Set<string>();
    const items = lines.map(line => {
      const key = json([line.product_id,line.size,line.color]);
      requireValue(!identities.has(key), 400, 'Combine duplicate cart lines.'); identities.add(key);
      const row = this.get(line.product_id), product = this.dto(row);
      requireValue(product.sizes.includes(line.size) && product.colors.some((c: { name: string }) => c.name === line.color), 400, `Choose valid options for ${product.name}.`, 'INVALID_OPTION');
      byProduct.set(row.id, (byProduct.get(row.id) || 0) + line.quantity);
      return { product_id: row.id, product_name: product.name, product_image: product.image_url || '', size: line.size, color: line.color, quantity: line.quantity, price: row.price };
    });
    if (checkStock) for (const [productId, quantity] of byProduct) {
      const product = this.dto(this.get(productId));
      requireValue(product.stock >= quantity, 409, `${product.name}: only ${product.stock} available.`, 'STOCK_CONFLICT');
    }
    return { items, byProduct };
  }
}
