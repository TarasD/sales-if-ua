package sales.bucket.service;

import sales.bucket.domain.Bucket;

import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
public interface BucketService {

    List<Bucket> getAll();

    Bucket getOne(Long id);

    Bucket getOneByClientId(Long userId);
}
