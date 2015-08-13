package sales.bucket.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import sales.bucket.domain.Bucket;
import sales.bucket.repository.BucketRepository;
import sales.users.domain.User;
import sales.users.service.UserService;

import java.util.List;

/**
 * Created by taras on 13.08.15.
 */
@Service("bucketService")
public class BucketServiceImpl implements BucketService {

    @Autowired
    BucketRepository bucketRepository;

    @Autowired
    UserService userService;

    @Override
    public List<Bucket> getAll() {
        return bucketRepository.findAll();
    }

    @Override
    public Bucket getOne(Long id) {
        return bucketRepository.findOne(id);
    }

    @Override
    public Bucket getOneByClientId(Long userId) {
        User client = userService.getById(userId);
        return bucketRepository.findByClient(client);
    }
}
